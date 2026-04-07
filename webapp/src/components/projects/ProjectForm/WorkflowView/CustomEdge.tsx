'use client'

import { memo } from 'react'
import { BaseEdge, getSmoothStepPath, type EdgeProps } from '@xyflow/react'

function CustomEdgeComponent({
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  animated,
  markerEnd,
}: EdgeProps) {
  const [edgePath] = getSmoothStepPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    borderRadius: 16,
  })

  const stroke = (style as Record<string, unknown>).stroke as string ?? '#888'
  const strokeWidth = (style as Record<string, unknown>).strokeWidth as number ?? 1.5
  const opacity = (style as Record<string, unknown>).opacity as number ?? 0.5
  const strokeDasharray = (style as Record<string, unknown>).strokeDasharray as string ?? '6 3'

  return (
    <g>
      <path
        d={edgePath}
        fill="none"
        stroke={stroke}
        strokeWidth={strokeWidth}
        opacity={opacity}
        strokeDasharray={strokeDasharray}
        className={animated ? 'workflow-edge-animated' : undefined}
      />
      <path
        d={edgePath}
        fill="none"
        stroke="transparent"
        strokeWidth={20}
      />
    </g>
  )
}

export const CustomEdge = memo(CustomEdgeComponent)
