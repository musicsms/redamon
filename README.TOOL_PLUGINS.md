# RedAmon Agentic Tool Plugin System

A standardized, modular way to add tools to the RedAmon AI agent. Drop a YAML file, restart the agent, and the tool is available.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Three Ways to Add a Tool](#three-ways-to-add-a-tool)
- [YAML Plugin Format](#yaml-plugin-format)
- [Current Tool Architecture](#current-tool-architecture)
- [Examples](#examples)
- [Implementation Details](#implementation-details)

---

## Quick Start

1. Create a YAML file in `plugins/agentic/tools/`
2. Restart the agent: `docker compose restart agent`
3. The AI agent can now discover and use your tool

---

## Three Ways to Add a Tool

### Way 1: Tool Already Installed in Kali Sandbox

Many tools come pre-installed in the kali-sandbox image (sqlmap, john, searchsploit, smbclient, etc.). To expose one as a **dedicated agent tool** (instead of relying on `kali_shell`):

```
1. Create plugins/agentic/tools/my_tool.yaml   (invocation: kali_shell)
2. docker compose restart agent
3. Done
```

**When to use**: The tool is already in the Kali image, you just want the LLM to know about it and use it by name.

### Way 2: Tool Needs Installing in Kali

For tools NOT in the default Kali image:

```
1. Add install commands to mcp/kali-sandbox/Dockerfile
2. Create plugins/agentic/tools/my_tool.yaml    (invocation: kali_shell)
3. docker compose build kali-sandbox
4. docker compose up -d kali-sandbox agent
5. Done
```

**When to use**: You want the tool running natively inside the Kali sandbox for best performance and integration.

### Way 3: Docker-Based Tool (No Kali Changes)

Run any tool from a Docker image without modifying the Kali sandbox:

```
1. Create plugins/agentic/tools/my_tool.yaml    (invocation: docker)
2. docker compose restart agent
3. Done — the tool runs as a sibling Docker container
```

**When to use**: You don't want to modify the Kali image, or the tool has a well-maintained Docker image.

---

## YAML Plugin Format

### Minimal Example (tool already in Kali)

```yaml
# plugins/agentic/tools/whatweb.yaml
id: whatweb
name: WhatWeb
invocation: kali_shell
phases:
  - informational
  - exploitation
  - post_exploitation
tool_name: execute_whatweb
purpose: "Web technology identification"
when_to_use: "Identify CMS, frameworks, web servers on a target"
args_format: '"args": "whatweb arguments"'
description: |
  **execute_whatweb** (Web Technology Fingerprinter)
  - Identifies websites: CMS, frameworks, JS libs, servers
  - Example args: "http://target.com"
  - Example args: "--aggression 3 -v http://target.com"
```

### Full Example (Docker-based tool)

```yaml
# plugins/agentic/tools/ffuf.yaml
id: ffuf
name: ffuf
invocation: docker
docker:
  image: ghcr.io/ffuf/ffuf:latest
  network_mode: host
  timeout: 300
phases:
  - informational
  - exploitation
  - post_exploitation
tool_name: execute_ffuf
purpose: "Web fuzzer for directories, vhosts, parameters"
when_to_use: "Discover hidden directories, files, vhosts, or parameters on a web target"
args_format: '"args": "ffuf arguments without ffuf prefix"'
description: |
  **execute_ffuf** (Web Fuzzer)
  - Fast web fuzzer for directory/file discovery, vhost enumeration, parameter fuzzing
  - Use FUZZ keyword as placeholder in the URL
  - Example args: "-u http://target/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302"
  - Example args: "-u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
  - Example args: "-u http://target/ -H 'Host: FUZZ.target.com' -w subdomains.txt -mc 200"
```

### Full Example (tool to install in Kali)

```yaml
# plugins/agentic/tools/testssl.yaml
id: testssl
name: testssl.sh
invocation: kali_shell
# Remember to add to Dockerfile: RUN apt-get install -y testssl.sh
# OR: RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
phases:
  - informational
  - exploitation
  - post_exploitation
tool_name: execute_testssl
purpose: "TLS/SSL configuration analysis"
when_to_use: "Analyze TLS/SSL configuration, detect weak ciphers, expired certs, known vulns"
args_format: '"args": "testssl.sh arguments"'
description: |
  **execute_testssl** (TLS/SSL Analyzer)
  - Comprehensive TLS/SSL testing (ciphers, protocols, vulnerabilities)
  - Checks for Heartbleed, POODLE, BEAST, CRIME, ROBOT, etc.
  - Example args: "https://target.com"
  - Example args: "--severity HIGH https://target.com"
  - Example args: "-p -s -S -P https://target.com"  (protocols + ciphers)
```

### YAML Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique snake_case identifier |
| `name` | Yes | Human-readable display name |
| `invocation` | Yes | `kali_shell` or `docker` |
| `phases` | Yes | List of phases: `informational`, `exploitation`, `post_exploitation` |
| `tool_name` | Yes | Name the LLM sees and calls (convention: `execute_<id>`) |
| `purpose` | Yes | One-line purpose (shown in tool summary) |
| `when_to_use` | Yes | Guidance for when the LLM should pick this tool |
| `args_format` | Yes | JSON argument format the LLM must use |
| `description` | Yes | Multi-line tool description with examples (shown to LLM) |
| `docker` | Only for `invocation: docker` | Docker execution config |
| `docker.image` | Yes (if docker) | Docker image to use |
| `docker.network_mode` | No | `host` (default), `bridge`, `none` |
| `docker.timeout` | No | Max execution time in seconds (default: 120) |

---

## Current Tool Architecture

### Core Tools (always active, not pluggable)

These tools are fundamental to the agent and are **NOT managed as plugins**. They are always available:

| Tool | Type | Why it's core |
|------|------|---------------|
| `query_graph` | Native (LangChain) | Primary data source — Neo4j graph queries |
| `web_search` | Native (LangChain) | External research — Tavily web search |
| `kali_shell` | MCP (network_recon) | General shell — backbone for kali_shell plugins |
| `execute_code` | MCP (network_recon) | Code execution — multi-language, no shell escaping |
| `metasploit_console` | MCP (metasploit) | Stateful exploitation — persistent sessions |
| `msf_restart` | MCP (metasploit) | Metasploit lifecycle management |

### Current Dedicated Tools (candidates for plugin migration)

These tools currently have dedicated MCP `@mcp.tool()` endpoints but could be refactored into plugins for modularity:

| Tool | Current Location | Plugin Migration |
|------|-----------------|------------------|
| `execute_curl` | `network_recon_server.py` | Candidate — simple CLI wrapper |
| `execute_naabu` | `network_recon_server.py` | Candidate — simple CLI wrapper |
| `execute_hydra` | `network_recon_server.py` | Keep as MCP — has progress streaming |
| `execute_nmap` | `nmap_server.py` | Candidate — simple CLI wrapper |
| `execute_nuclei` | `nuclei_server.py` | Candidate — simple CLI wrapper |

The tools marked "Candidate" follow the exact same pattern: take `args` string, run `subprocess.run([tool] + shlex.split(args))`, return output. This is exactly what the plugin system standardizes.

### MCP Server Architecture

```
kali-sandbox container
  |
  |-- network_recon_server.py (port 8000)
  |     execute_curl, execute_naabu, kali_shell, execute_code, execute_hydra
  |
  |-- nuclei_server.py (port 8002)
  |     execute_nuclei
  |
  |-- metasploit_server.py (port 8003)
  |     metasploit_console, msf_restart
  |
  |-- nmap_server.py (port 8004)
  |     execute_nmap
  |
  |-- [NEW] plugin_executor.py (port 8005)  <-- handles all plugin tools
        execute_plugin(tool_id, args)
```

---

## How Plugins Integrate

### Registration Flow

```
Agent startup
  |
  |--> plugins/agentic/loader.py scans tools/*.yaml
  |
  |--> For each valid plugin:
  |      1. Adds entry to TOOL_REGISTRY (tool_registry.py)
  |         -> LLM sees the tool in its prompt
  |      2. Adds entry to TOOL_PHASE_MAP (project_settings.py)
  |         -> Phase restrictions enforced
  |      3. Registers in PhaseAwareToolExecutor (tools.py)
  |         -> Tool is callable
  |
  |--> Agent ready, plugins active
```

### Execution Flow

```
LLM decides to use "execute_ffuf"
  |
  |--> PhaseAwareToolExecutor.execute("execute_ffuf", {"args": "-u http://..."}, phase)
  |
  |--> Looks up plugin by tool_name
  |
  |--> If invocation == "kali_shell":
  |      Calls kali_shell MCP tool with command="ffuf <args>"
  |
  |--> If invocation == "docker":
  |      Calls execute_plugin MCP tool with tool_id="ffuf", args="<args>"
  |      -> Builds: docker run --rm --net=host ghcr.io/ffuf/ffuf <args>
  |      -> Returns output
  |
  |--> Output returned to LLM for analysis
```

---

## Examples

### Example 1: Add sqlmap as a dedicated tool

sqlmap is already installed in Kali but currently only accessible via `kali_shell`. Making it a dedicated tool gives the LLM better guidance:

```yaml
# plugins/agentic/tools/sqlmap.yaml
id: sqlmap
name: SQLMap
invocation: kali_shell
phases:
  - informational
  - exploitation
  - post_exploitation
tool_name: execute_sqlmap
purpose: "Automatic SQL injection detection and exploitation"
when_to_use: "Detect and exploit SQL injection vulnerabilities in web applications"
args_format: '"args": "sqlmap arguments without sqlmap prefix"'
description: |
  **execute_sqlmap** (SQL Injection Scanner)
  - Automatic SQL injection detection and exploitation
  - Supports MySQL, PostgreSQL, MSSQL, Oracle, SQLite
  - Always use --batch for non-interactive mode
  - Example args: "-u 'http://target/page?id=1' --batch --dbs"
  - Example args: "-u 'http://target/page?id=1' --batch --dump -D dbname -T users"
  - Example args: "-r /tmp/request.txt --batch --level 5 --risk 3"
  - Example args: "-u 'http://target/page?id=1' --batch --os-shell"
```

### Example 2: Add gobuster via Docker

```yaml
# plugins/agentic/tools/gobuster.yaml
id: gobuster
name: Gobuster
invocation: docker
docker:
  image: ghcr.io/oj/gobuster:latest
  network_mode: host
  timeout: 300
phases:
  - informational
  - exploitation
  - post_exploitation
tool_name: execute_gobuster
purpose: "Directory and DNS brute-forcing"
when_to_use: "Brute-force directories, files, DNS subdomains, or vhosts on a target"
args_format: '"args": "gobuster arguments without gobuster prefix"'
description: |
  **execute_gobuster** (Directory & DNS Brute-Forcer)
  - Brute-force directories, files, DNS subdomains, vhosts, S3 buckets
  - Modes: dir (directory), dns (subdomain), vhost, fuzz, s3
  - Example args: "dir -u http://target -w /usr/share/wordlists/dirb/common.txt"
  - Example args: "dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  - Example args: "dir -u http://target -w wordlist.txt -x php,txt,html -t 50"
```

### Example 3: Add wafw00f (install in Kali)

First, add to `mcp/kali-sandbox/Dockerfile`:
```dockerfile
# After the pip install line, add:
RUN pip install wafw00f
```

Then create the plugin:
```yaml
# plugins/agentic/tools/wafw00f.yaml
id: wafw00f
name: wafw00f
invocation: kali_shell
phases:
  - informational
  - exploitation
  - post_exploitation
tool_name: execute_wafw00f
purpose: "Web Application Firewall detection"
when_to_use: "Detect if a target is behind a WAF and identify the WAF product"
args_format: '"args": "wafw00f arguments"'
description: |
  **execute_wafw00f** (WAF Detector)
  - Identifies Web Application Firewalls (Cloudflare, AWS WAF, ModSecurity, etc.)
  - Useful before exploitation to adjust attack techniques
  - Example args: "http://target.com"
  - Example args: "-a http://target.com"  (test all WAFs, not just first match)
  - Example args: "-l"  (list all detectable WAFs)
```

### Example 4: Add nikto (install in Kali)

Add to `mcp/kali-sandbox/Dockerfile`:
```dockerfile
RUN apt-get update && apt-get install -y nikto && rm -rf /var/lib/apt/lists/*
```

```yaml
# plugins/agentic/tools/nikto.yaml
id: nikto
name: Nikto
invocation: kali_shell
phases:
  - informational
  - exploitation
  - post_exploitation
tool_name: execute_nikto
purpose: "Web server vulnerability scanner"
when_to_use: "Scan web servers for dangerous files, outdated software, misconfigurations"
args_format: '"args": "nikto arguments without nikto prefix"'
description: |
  **execute_nikto** (Web Server Scanner)
  - Comprehensive web server scanner (6700+ dangerous files/programs)
  - Checks for outdated server versions, configuration issues
  - Example args: "-h http://target.com"
  - Example args: "-h http://target.com -p 8080"
  - Example args: "-h http://target.com -Tuning 9"  (SQL injection tests only)
  - Example args: "-h http://target.com -ssl"  (force SSL)
```

### Example 5: Add subfinder via Docker

```yaml
# plugins/agentic/tools/subfinder.yaml
id: subfinder
name: Subfinder
invocation: docker
docker:
  image: projectdiscovery/subfinder:latest
  network_mode: host
  timeout: 300
phases:
  - informational
  - exploitation
  - post_exploitation
tool_name: execute_subfinder
purpose: "Passive subdomain discovery"
when_to_use: "Discover subdomains using passive sources (no direct target contact)"
args_format: '"args": "subfinder arguments without subfinder prefix"'
description: |
  **execute_subfinder** (Passive Subdomain Discovery)
  - Discovers subdomains using passive sources (certificate transparency, APIs, archives)
  - No direct contact with target — fully passive
  - Sources: Shodan, Censys, VirusTotal, SecurityTrails, and more
  - Example args: "-d target.com -json"
  - Example args: "-d target.com -all -json"
  - Example args: "-d target.com -sources shodan,censys -json"
```

---

## Implementation Details

### File Structure

```
plugins/
  agentic/
    __init__.py
    loader.py           # Discovers and validates YAML files
    schema.py           # Pydantic model for YAML validation
    tools/
      _template.yaml    # Blank template — copy this to start
      sqlmap.yaml       # Example: kali_shell tool
      ffuf.yaml         # Example: docker tool
      ...
```

### Plugin Loader (`plugins/agentic/loader.py`)

- Scans `plugins/agentic/tools/*.yaml` at agent startup
- Validates each file against Pydantic schema
- Logs warnings for invalid files (does NOT crash the agent)
- Returns list of validated `ToolPlugin` objects

### Integration Points

**3 files modified to support plugins:**

1. **`agentic/prompts/tool_registry.py`** — Merges plugin entries into `TOOL_REGISTRY` so the LLM sees them in its prompt

2. **`agentic/project_settings.py`** — Merges plugin phases into `TOOL_PHASE_MAP` so phase restrictions are enforced

3. **`agentic/tools.py`** — Registers plugin tools in `PhaseAwareToolExecutor` so they can be called

**1 new MCP endpoint for Docker-based plugins:**

4. **`mcp/servers/network_recon_server.py`** — New `execute_plugin(tool_id, args)` endpoint that builds and runs Docker commands from plugin YAML config

### Volume Mount

`docker-compose.yml` mounts `./plugins:/app/plugins:ro` into both `agent` and `kali-sandbox` containers so they can read plugin YAML files.

---

## Migrating Existing Tools to Plugins

The following tools currently have dedicated MCP endpoints but are simple CLI wrappers. They can optionally be migrated to plugins:

### Before (hardcoded in `network_recon_server.py`):
```python
@mcp.tool()
def execute_curl(args: str) -> str:
    result = subprocess.run(["curl"] + shlex.split(args), ...)
    return result.stdout
```

### After (YAML plugin):
```yaml
# plugins/agentic/tools/curl.yaml
id: curl
name: curl
invocation: kali_shell
phases: [informational, exploitation, post_exploitation]
tool_name: execute_curl
purpose: "HTTP requests & vuln probing"
when_to_use: "Reachability checks + vulnerability testing as FALLBACK"
args_format: '"args": "curl arguments without curl prefix"'
description: |
  **execute_curl** (HTTP Client)
  ...
```

**Migration is optional and incremental.** Core MCP tools keep working. Plugins add new tools alongside them. Over time, simple CLI wrapper tools can be migrated one by one.

### Tools NOT to migrate (keep as core MCP):

| Tool | Reason |
|------|--------|
| `kali_shell` | Backbone of the plugin system — plugins delegate to it |
| `execute_code` | Complex logic (file writing, compilation, multi-language) |
| `execute_hydra` | Has progress streaming server (port 8014) |
| `metasploit_console` | Stateful persistent sessions, progress streaming |
| `msf_restart` | Metasploit lifecycle management |
| `query_graph` | Native LangChain tool with Neo4j + tenant filtering |
| `web_search` | Native LangChain tool with Tavily API |

---

## reconFTW Tools — Plugin Candidates

Tools from [reconFTW](https://github.com/six2dez/reconftw) that can be added as plugins:

### Subdomain Enumeration
| Tool | Invocation | Notes |
|------|-----------|-------|
| subfinder | docker (`projectdiscovery/subfinder`) | Passive subdomain discovery |
| dnsx | docker (`projectdiscovery/dnsx`) | DNS resolution and bruteforce |
| tlsx | docker (`projectdiscovery/tlsx`) | TLS certificate enumeration |
| hakip2host | kali_shell (install via `go install`) | Reverse IP lookup |

### Web Analysis
| Tool | Invocation | Notes |
|------|-----------|-------|
| ffuf | docker (`ghcr.io/ffuf/ffuf`) | Directory/parameter fuzzing |
| gobuster | docker (`ghcr.io/oj/gobuster`) | Directory brute-force |
| whatweb | kali_shell (pre-installed in Kali) | Technology fingerprinting |
| wafw00f | kali_shell (`pip install wafw00f`) | WAF detection |
| nikto | kali_shell (`apt install nikto`) | Web server scanning |
| CMSeeK | kali_shell (`pip install CMSeeK`) | CMS detection |
| testssl.sh | kali_shell (`apt install testssl.sh`) | TLS/SSL analysis |

### Vulnerability Scanning
| Tool | Invocation | Notes |
|------|-----------|-------|
| dalfox | docker (`hahwul/dalfox`) | XSS scanner |
| crlfuzz | docker (`projectdiscovery/crlfuzz`) | CRLF injection |
| commix | kali_shell (`apt install commix`) | Command injection |
| sqlmap | kali_shell (already installed) | SQL injection (already in Kali!) |

### Secret Scanning
| Tool | Invocation | Notes |
|------|-----------|-------|
| trufflehog | docker (`trufflesecurity/trufflehog`) | Secrets in repos/filesystems |
| gitleaks | docker (`zricethezav/gitleaks`) | Git history secrets |

### Infrastructure
| Tool | Invocation | Notes |
|------|-----------|-------|
| cdncheck | docker (`projectdiscovery/cdncheck`) | CDN detection |
| brutespray | kali_shell (`apt install brutespray`) | Auto-brute-force from nmap |

---

## Writing Good Tool Descriptions

The `description` field is what the LLM reads to decide when and how to use your tool. Good descriptions include:

1. **Bold tool name** with category in parentheses
2. **What it does** in 2-3 bullet points
3. **When to use vs alternatives** (e.g., "Use instead of kali_shell for structured SQLi testing")
4. **3+ example args** covering common use cases
5. **Key flags** the LLM should know about

### Good description:
```yaml
description: |
  **execute_sqlmap** (SQL Injection Scanner)
  - Automatic SQL injection detection and exploitation
  - Supports MySQL, PostgreSQL, MSSQL, Oracle, SQLite
  - Always use --batch for non-interactive mode
  - Example args: "-u 'http://target/page?id=1' --batch --dbs"
  - Example args: "-u 'http://target/page?id=1' --batch --dump -D dbname"
  - Example args: "-r /tmp/request.txt --batch --level 5 --risk 3"
```

### Bad description:
```yaml
description: "SQLMap is an SQL injection tool"
# Too short — LLM won't know flags, examples, or when to prefer this over kali_shell
```

---

## Blank Template

Copy `plugins/agentic/tools/_template.yaml` to get started:

```yaml
# plugins/agentic/tools/_template.yaml
# Copy this file and rename it to your tool name (e.g., mytool.yaml)

id: my_tool                    # Unique snake_case ID
name: My Tool                  # Display name

# How the tool runs:
#   kali_shell — tool is installed in Kali sandbox (or will be added to Dockerfile)
#   docker     — tool runs as a Docker container
invocation: kali_shell

# For Docker-based tools only:
# docker:
#   image: author/tool:latest
#   network_mode: host
#   timeout: 300

# Which agent phases can use this tool:
phases:
  - informational
  - exploitation
  - post_exploitation

# Tool identity for the LLM:
tool_name: execute_my_tool     # Convention: execute_<id>
purpose: "Brief one-line purpose"
when_to_use: "When should the LLM pick this tool over others?"
args_format: '"args": "tool arguments without tool name prefix"'
description: |
  **execute_my_tool** (Category)
  - What the tool does
  - Key capability
  - Example args: "-flag1 value http://target"
  - Example args: "--option http://target"
```
