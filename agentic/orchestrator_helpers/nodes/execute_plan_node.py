"""Execute plan node — runs a wave of independent tools in parallel.

This node emits streaming events directly to the callback (not through
emit_streaming_events in streaming.py) because it manages multiple tool
lifecycles in a single node execution.
"""

import asyncio
import os
import re
import logging
from uuid import uuid4

import httpx

from state import AgentState
from orchestrator_helpers.config import get_identifiers
from tools import set_tenant_context, set_phase_context, set_graph_view_context

logger = logging.getLogger(__name__)


def _check_roe_blocked(tool_name: str, phase: str) -> str | None:
    """Check if a tool is blocked by Rules of Engagement. Returns error message or None."""
    from project_settings import get_setting

    if not get_setting('ROE_ENABLED', False):
        return None

    CATEGORY_TOOL_MAP = {
        'brute_force': ['execute_hydra', 'execute_wpscan'],
        'dos': [],
        'social_engineering': [],
        'exploitation': ['metasploit_console', 'execute_hydra'],
    }
    forbidden = set(get_setting('ROE_FORBIDDEN_TOOLS', []))
    for cat in get_setting('ROE_FORBIDDEN_CATEGORIES', []):
        forbidden.update(CATEGORY_TOOL_MAP.get(cat, []))

    if not get_setting('ROE_ALLOW_ACCOUNT_LOCKOUT', False):
        forbidden.add('execute_hydra')
    if not get_setting('ROE_ALLOW_DOS', False):
        forbidden.update(CATEGORY_TOOL_MAP.get('dos', []))

    if tool_name in forbidden:
        return f"RoE BLOCKED: Tool '{tool_name}' is forbidden by the Rules of Engagement."

    PHASE_ORDER = {'informational': 0, 'exploitation': 1, 'post_exploitation': 2}
    max_phase = get_setting('ROE_MAX_SEVERITY_PHASE', 'post_exploitation')
    if PHASE_ORDER.get(phase, 0) > PHASE_ORDER.get(max_phase, 2):
        return f"RoE BLOCKED: Current phase '{phase}' exceeds maximum allowed phase '{max_phase}'."

    return None


async def _execute_single_step(
    step: dict,
    step_index: int,
    total_steps: int,
    *,
    phase: str,
    wave_id: str,
    user_id: str,
    project_id: str,
    session_id: str,
    tool_executor,
    streaming_cb,
    session_manager_base: str,
) -> bool:
    """Execute a single tool step within a wave. Returns True if successful."""
    tool_name = step.get("tool_name")
    tool_args = step.get("tool_args") or {}

    logger.info(f"\n--- Plan Step {step_index+1}/{total_steps}: {tool_name} ---")

    if not tool_name:
        step["tool_output"] = "Error: No tool specified"
        step["success"] = False
        step["error_message"] = "No tool name provided"
        return False

    # RoE gate
    roe_msg = _check_roe_blocked(tool_name, phase)
    if roe_msg:
        logger.warning(f"[{user_id}/{project_id}/{session_id}] {roe_msg}")
        step["tool_output"] = roe_msg
        step["success"] = False
        step["error_message"] = roe_msg
        if streaming_cb:
            try:
                await streaming_cb.on_tool_start(tool_name, tool_args, wave_id=wave_id, step_index=step_index)
                await streaming_cb.on_tool_complete(
                    tool_name, False, roe_msg, wave_id=wave_id, step_index=step_index,
                )
            except Exception as e:
                logger.warning(f"Error emitting RoE block events: {e}")
        return False

    # Emit tool_start
    if streaming_cb:
        try:
            await streaming_cb.on_tool_start(tool_name, tool_args, wave_id=wave_id, step_index=step_index)
        except Exception as e:
            logger.warning(f"Error emitting tool_start: {e}")

    # Execute the tool
    try:
        is_long_running_msf = (
            tool_name == "metasploit_console" and
            any(cmd in (tool_args.get("command", "") or "").lower() for cmd in ["run", "exploit"])
        )
        is_long_running_hydra = (tool_name == "execute_hydra")

        # Create a wave-aware progress callback
        async def _wave_progress(tn, chunk, is_final=False, _wid=wave_id, _si=step_index):
            if streaming_cb:
                await streaming_cb.on_tool_output_chunk(tn, chunk, is_final=is_final, wave_id=_wid, step_index=_si)

        if is_long_running_msf and streaming_cb:
            result = await tool_executor.execute_with_progress(
                tool_name, tool_args, phase,
                progress_callback=_wave_progress,
            )
        elif is_long_running_hydra and streaming_cb:
            result = await tool_executor.execute_with_progress(
                tool_name, tool_args, phase,
                progress_callback=_wave_progress,
                progress_url=os.environ.get('MCP_HYDRA_PROGRESS_URL', 'http://kali-sandbox:8014/progress'),
            )
        else:
            result = await tool_executor.execute(tool_name, tool_args, phase)
    except Exception as e:
        logger.error(f"Tool execution error for {tool_name}: {e}")
        result = {"success": False, "error": str(e), "output": f"Error: {e}"}

    # Store result
    if result:
        step["tool_output"] = result.get("output") or ""
        step["success"] = result.get("success", False)
        step["error_message"] = result.get("error")
    else:
        step["tool_output"] = ""
        step["success"] = False
        step["error_message"] = "Tool execution returned no result"

    tool_output = step.get("tool_output", "")

    # Emit output as chunk for non-streaming tools so frontend shows Raw Output
    is_long_running = is_long_running_msf or is_long_running_hydra
    if not is_long_running and streaming_cb and tool_output:
        try:
            await streaming_cb.on_tool_output_chunk(
                tool_name, tool_output, is_final=True, wave_id=wave_id, step_index=step_index,
            )
        except Exception as e:
            logger.warning(f"Error emitting tool output chunk: {e}")

    logger.info(f"  SUCCESS: {step['success']}")
    if step.get("error_message"):
        logger.info(f"  ERROR: {step['error_message']}")
    logger.info(f"  OUTPUT ({len(tool_output)} chars)")

    # Emit tool_complete (no output_summary — raw output already sent as chunk)
    if streaming_cb:
        try:
            await streaming_cb.on_tool_complete(
                tool_name,
                step["success"],
                "",
                wave_id=wave_id,
                step_index=step_index,
            )
        except Exception as e:
            logger.warning(f"Error emitting tool_complete: {e}")

    # Detect new Metasploit sessions
    if tool_name == "metasploit_console" and tool_output:
        for match in re.finditer(r'session\s+(\d+)\s+opened', tool_output, re.IGNORECASE):
            msf_session_id = int(match.group(1))
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{session_manager_base}/session-chat-map",
                        json={"msf_session_id": msf_session_id, "chat_session_id": session_id}
                    )
            except Exception:
                pass

    # Register non-MSF listeners
    if tool_name == "kali_shell" and tool_args:
        cmd = tool_args.get("command", "")
        if re.search(r'(nc|ncat)\s+.*-l', cmd) or 'socat' in cmd:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{session_manager_base}/non-msf-sessions",
                        json={"type": "listener", "tool": "netcat", "command": cmd,
                              "chat_session_id": session_id}
                    )
            except Exception:
                pass

    return step["success"]


async def execute_plan_node(
    state: AgentState,
    config,
    *,
    tool_executor,
    streaming_callbacks,
    session_manager_base,
    graph_view_cyphers=None,
) -> dict:
    """Execute a wave of independent tools in parallel using asyncio.gather."""
    user_id, project_id, session_id = get_identifiers(state, config)
    plan_data = state.get("_current_plan")

    if not plan_data or not plan_data.get("steps"):
        logger.error(f"[{user_id}/{project_id}/{session_id}] execute_plan_node called with no plan data")
        return {"_current_plan": None}

    steps = plan_data["steps"]
    phase = state.get("current_phase", "informational")
    iteration = state.get("current_iteration", 0)
    wave_id = f"wave-{iteration}-{uuid4().hex[:8]}"

    plan_data["wave_id"] = wave_id

    logger.info(f"\n{'='*60}")
    logger.info(f"EXECUTE PLAN (PARALLEL) - Iteration {iteration} - Phase: {phase}")
    logger.info(f"Wave ID: {wave_id} - {len(steps)} tools")
    logger.info(f"Tools: {[s.get('tool_name') for s in steps]}")
    logger.info(f"{'='*60}")

    # Set context (ContextVar — inherited by child tasks in asyncio)
    set_tenant_context(user_id, project_id)
    set_phase_context(phase)
    if graph_view_cyphers:
        set_graph_view_context(graph_view_cyphers.get(session_id))

    # Get streaming callback
    streaming_cb = streaming_callbacks.get(session_id)

    # Emit plan_start
    tool_names = [s.get("tool_name", "unknown") for s in steps]
    if streaming_cb:
        try:
            await streaming_cb.on_plan_start(
                wave_id=wave_id,
                plan_rationale=plan_data.get("plan_rationale", ""),
                tools=tool_names,
            )
        except Exception as e:
            logger.warning(f"Error emitting plan_start: {e}")

    # Execute all steps in parallel
    tasks = [
        _execute_single_step(
            step,
            i,
            len(steps),
            phase=phase,
            wave_id=wave_id,
            user_id=user_id,
            project_id=project_id,
            session_id=session_id,
            tool_executor=tool_executor,
            streaming_cb=streaming_cb,
            session_manager_base=session_manager_base,
        )
        for i, step in enumerate(steps)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Count successes/failures
    successful = 0
    failed = 0
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Unexpected exception in parallel step {i}: {result}")
            steps[i]["tool_output"] = steps[i].get("tool_output") or f"Error: {result}"
            steps[i]["success"] = False
            steps[i]["error_message"] = str(result)
            failed += 1
        elif result:
            successful += 1
        else:
            failed += 1

    # Emit plan_complete
    if streaming_cb:
        try:
            await streaming_cb.on_plan_complete(
                wave_id=wave_id,
                total=len(steps),
                successful=successful,
                failed=failed,
            )
        except Exception as e:
            logger.warning(f"Error emitting plan_complete: {e}")

    logger.info(f"\n{'='*60}")
    logger.info(f"PLAN COMPLETE (PARALLEL) - {successful} ok, {failed} failed out of {len(steps)}")
    logger.info(f"{'='*60}\n")

    return {"_current_plan": plan_data}
