import { useMemo } from 'react'
import type { Node, Edge } from '@xyflow/react'
import {
  WORKFLOW_TOOLS,
  UNIVERSAL_DATA_NODES,
  TRANSITIONAL_DATA_NODES,
  ALL_WORKFLOW_DATA_NODES,
  DATA_NODE_CATEGORIES,
  CATEGORY_COLORS,
  getGroupColor,
  getToolProduces,
  getToolConsumes,
} from './workflowDefinition'
import {
  computeLayout,
  TOOL_NODE_WIDTH,
  TOOL_NODE_HEIGHT,
  DATA_NODE_WIDTH,
  DATA_NODE_HEIGHT,
  INPUT_NODE_WIDTH,
  INPUT_NODE_HEIGHT,
} from './workflowLayout'

// Virtual Input node produces universal types
const INPUT_PRODUCES = ['Domain', 'Subdomain', 'IP']

export function useWorkflowGraph(formData: Record<string, unknown>) {
  // Extract all enabled fields into a stable dependency key
  const enabledKey = WORKFLOW_TOOLS.map(t => formData[t.enabledField] ? '1' : '0').join('')

  return useMemo(() => {
    // ---- 1. Build data node status (active vs starved) ----
    const dataNodeStatus = new Map<string, 'active' | 'starved'>()

    for (const nodeType of ALL_WORKFLOW_DATA_NODES) {
      if (UNIVERSAL_DATA_NODES.has(nodeType)) {
        // Universal nodes are always active (Input provides them)
        dataNodeStatus.set(nodeType, 'active')
        continue
      }

      // Transitional: check if any enabled tool is a TRUE SOURCE of this type.
      // A "true source" produces X without also consuming X.
      // Tools that both consume and produce the same type (e.g. Katana
      // consumes BaseURL and produces BaseURL) are recyclers/expanders,
      // not original sources -- they can't bootstrap from nothing.
      const hasTrueSource = WORKFLOW_TOOLS.some(
        t => formData[t.enabledField]
          && getToolProduces(t.id).includes(nodeType)
          && !getToolConsumes(t.id).includes(nodeType)
      )
      dataNodeStatus.set(nodeType, hasTrueSource ? 'active' : 'starved')
    }

    // ---- 2. Build tool chain-broken status ----
    const toolBrokenInputs = new Map<string, string[]>()

    for (const tool of WORKFLOW_TOOLS) {
      const consumed = getToolConsumes(tool.id)
      const starvedInputs = consumed.filter(
        t => TRANSITIONAL_DATA_NODES.has(t) && dataNodeStatus.get(t) === 'starved'
      )
      if (starvedInputs.length > 0) {
        toolBrokenInputs.set(tool.id, starvedInputs)
      }
    }

    // ---- 3. Determine which data nodes actually have connections ----
    const connectedDataNodes = new Set<string>()

    // Input produces universal types
    for (const nt of INPUT_PRODUCES) connectedDataNodes.add(nt)

    for (const tool of WORKFLOW_TOOLS) {
      for (const nt of getToolProduces(tool.id)) {
        if (ALL_WORKFLOW_DATA_NODES.has(nt)) connectedDataNodes.add(nt)
      }
      for (const nt of getToolConsumes(tool.id)) {
        if (ALL_WORKFLOW_DATA_NODES.has(nt)) connectedDataNodes.add(nt)
      }
    }

    // ---- 4. Build layout descriptors ----
    const layoutNodes: { id: string; type: 'input' | 'tool' | 'data'; group: number; width: number; height: number }[] = []

    // Input node
    layoutNodes.push({ id: 'input', type: 'input', group: 0, width: INPUT_NODE_WIDTH, height: INPUT_NODE_HEIGHT })

    // Tool nodes
    for (const tool of WORKFLOW_TOOLS) {
      layoutNodes.push({
        id: `tool-${tool.id}`,
        type: 'tool',
        group: tool.group,
        width: TOOL_NODE_WIDTH,
        height: TOOL_NODE_HEIGHT,
      })
    }

    // Data nodes
    for (const nodeType of connectedDataNodes) {
      layoutNodes.push({
        id: `data-${nodeType}`,
        type: 'data',
        group: 0, // group is computed inside computeLayout from the definition
        width: DATA_NODE_WIDTH,
        height: DATA_NODE_HEIGHT,
      })
    }

    // ---- 5. Compute positions ----
    const positions = computeLayout(layoutNodes)
    const posMap = new Map(positions.map(p => [p.id, { x: p.x, y: p.y }]))

    // ---- 6. Build edges ----
    const edgeEntries: { source: string; target: string }[] = []

    // Input --> universal data nodes
    for (const nt of INPUT_PRODUCES) {
      edgeEntries.push({ source: 'input', target: `data-${nt}` })
    }

    // Universal data nodes --> consuming tools
    for (const nt of UNIVERSAL_DATA_NODES) {
      if (!connectedDataNodes.has(nt)) continue
      for (const tool of WORKFLOW_TOOLS) {
        if (getToolConsumes(tool.id).includes(nt)) {
          edgeEntries.push({ source: `data-${nt}`, target: `tool-${tool.id}` })
        }
      }
    }

    // Tool --> data node (produces) -- both transitional AND universal
    // Tools that produce universal types (e.g. SubdomainDiscovery produces
    // Subdomain, OSINT Enrichment produces IP) get output edges to those
    // data nodes, showing they contribute new data.
    for (const tool of WORKFLOW_TOOLS) {
      for (const nt of getToolProduces(tool.id)) {
        if (connectedDataNodes.has(nt)) {
          edgeEntries.push({ source: `tool-${tool.id}`, target: `data-${nt}` })
        }
      }
    }

    // Transitional data node --> consuming tool
    for (const nt of TRANSITIONAL_DATA_NODES) {
      if (!connectedDataNodes.has(nt)) continue
      for (const tool of WORKFLOW_TOOLS) {
        if (getToolConsumes(tool.id).includes(nt)) {
          edgeEntries.push({ source: `data-${nt}`, target: `tool-${tool.id}` })
        }
      }
    }

    // Deduplicate edges
    const edgeSet = new Set(edgeEntries.map(e => `${e.source}|${e.target}`))
    const uniqueEdges = [...edgeSet].map(key => {
      const [source, target] = key.split('|')
      return { source, target }
    })

    // ---- 7. Build React Flow nodes ----
    const rfNodes: Node[] = []

    // Input node
    const inputPos = posMap.get('input') ?? { x: 0, y: 0 }
    rfNodes.push({
      id: 'input',
      type: 'inputNode',
      position: inputPos,
      data: { label: 'Target Input' },
      draggable: false,
      selectable: false,
    })

    // Tool nodes
    for (const tool of WORKFLOW_TOOLS) {
      const pos = posMap.get(`tool-${tool.id}`) ?? { x: 0, y: 0 }
      const enabled = !!formData[tool.enabledField]
      const brokenInputs = toolBrokenInputs.get(tool.id) ?? []
      rfNodes.push({
        id: `tool-${tool.id}`,
        type: 'toolNode',
        position: pos,
        data: {
          toolId: tool.id,
          label: tool.label,
          enabled,
          enabledField: tool.enabledField,
          group: tool.group,
          badge: tool.badge,
          chainBroken: !enabled ? false : brokenInputs.length > 0,
          starvedInputs: brokenInputs,
          groupColor: getGroupColor(tool.group),
        },
        draggable: false,
        selectable: false,
      })
    }

    // Data nodes
    for (const nodeType of connectedDataNodes) {
      const pos = posMap.get(`data-${nodeType}`) ?? { x: 0, y: 0 }
      const isUniversal = UNIVERSAL_DATA_NODES.has(nodeType)
      const status = dataNodeStatus.get(nodeType) ?? 'active'
      const category = DATA_NODE_CATEGORIES[nodeType] ?? 'identity'
      const color = CATEGORY_COLORS[category]

      // Compute producer/consumer lists for tooltip
      const producers = isUniversal
        ? ['Input']
        : WORKFLOW_TOOLS.filter(t => getToolProduces(t.id).includes(nodeType)).map(t => t.label)
      const consumers = WORKFLOW_TOOLS.filter(t => getToolConsumes(t.id).includes(nodeType)).map(t => t.label)

      rfNodes.push({
        id: `data-${nodeType}`,
        type: 'dataNode',
        position: pos,
        data: {
          nodeType,
          isUniversal,
          status,
          category,
          color,
          producers,
          consumers,
        },
        draggable: false,
        selectable: false,
      })
    }

    // ---- 8. Build React Flow edges ----
    // All edges are dashed. Animated dashes show direction when the
    // producing tool is enabled (data flows from tool to data node,
    // and from data node to consuming tool).
    const rfEdges: Edge[] = uniqueEdges.map((edge, i) => {
      const sourceIsData = edge.source.startsWith('data-')
      const targetIsData = edge.target.startsWith('data-')

      let animated = false
      let strokeColor = '#4b5563'
      let strokeOpacity = 0.6
      const strokeDasharray = '6 3'

      if (sourceIsData) {
        // data --> tool (input edge)
        const dataType = edge.source.replace('data-', '')
        const status = dataNodeStatus.get(dataType)
        const category = DATA_NODE_CATEGORIES[dataType]

        if (status === 'starved') {
          strokeColor = '#ef4444'
          strokeOpacity = 0.4
        } else {
          strokeColor = CATEGORY_COLORS[category] ?? '#22c55e'
          // Animate if the consuming tool is enabled
          const toolId = edge.target.replace('tool-', '')
          const tool = WORKFLOW_TOOLS.find(t => t.id === toolId)
          const toolEnabled = tool ? !!formData[tool.enabledField] : false
          animated = toolEnabled
          strokeOpacity = toolEnabled ? 0.5 : 0.15
        }
      } else if (targetIsData) {
        // tool/input --> data (output edge)
        const dataType = edge.target.replace('data-', '')
        const category = DATA_NODE_CATEGORIES[dataType]

        if (edge.source === 'input') {
          strokeColor = CATEGORY_COLORS[category] ?? '#3b82f6'
          strokeOpacity = 0.4
          animated = true
        } else {
          const toolId = edge.source.replace('tool-', '')
          const tool = WORKFLOW_TOOLS.find(t => t.id === toolId)
          const enabled = tool ? !!formData[tool.enabledField] : false
          strokeColor = enabled
            ? (CATEGORY_COLORS[category] ?? '#22c55e')
            : '#4b5563'
          strokeOpacity = enabled ? 0.5 : 0.15
          animated = enabled
        }
      }

      return {
        id: `e-${i}`,
        source: edge.source,
        target: edge.target,
        type: 'custom',
        animated,
        style: {
          stroke: strokeColor,
          strokeWidth: 1.5,
          strokeDasharray,
          opacity: strokeOpacity,
        },
      }
    })

    return { nodes: rfNodes, edges: rfEdges, dataNodeStatus }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabledKey])
}
