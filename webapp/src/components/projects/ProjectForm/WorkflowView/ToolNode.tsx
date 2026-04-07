'use client'

import { memo, useCallback } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { AlertTriangle, Settings } from 'lucide-react'
import styles from './WorkflowView.module.css'

interface ToolNodeData {
  toolId: string
  label: string
  enabled: boolean
  enabledField: string
  group: number
  badge?: 'active' | 'passive' | 'both'
  chainBroken: boolean
  starvedInputs: string[]
  groupColor: string
  onToggle?: (field: string, value: boolean) => void
  onOpenSettings?: (toolId: string) => void
  onNodeClick?: (nodeId: string) => void
  highlighted?: boolean
  dimmed?: boolean
}

function ToolNodeComponent({ data }: NodeProps) {
  const {
    toolId,
    label,
    enabled,
    enabledField,
    badge,
    chainBroken,
    starvedInputs,
    groupColor,
    onToggle,
    onOpenSettings,
    onNodeClick,
    highlighted,
    dimmed,
  } = data as unknown as ToolNodeData

  const handleToggle = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    onToggle?.(enabledField, !enabled)
  }, [onToggle, enabledField, enabled])

  const handleSettingsClick = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    onOpenSettings?.(toolId)
  }, [onOpenSettings, toolId])

  const handleClick = useCallback(() => {
    onNodeClick?.(`tool-${toolId}`)
  }, [onNodeClick, toolId])

  return (
    <div
      className={`${styles.toolNode} ${!enabled ? styles.toolNodeDisabled : ''} ${chainBroken ? styles.toolNodeBroken : ''} ${highlighted ? styles.toolNodeHighlighted : ''} ${dimmed ? styles.toolNodeDimmed : ''}`}
      style={{ borderLeftColor: groupColor }}
      onClick={handleClick}
      title={chainBroken ? `${label} requires ${starvedInputs.join(', ')} data but no active tool is producing ${starvedInputs.length > 1 ? 'them' : 'it'}. Enable a tool that generates ${starvedInputs.join('/')} to fix this.` : undefined}
    >
      <Handle type="target" position={Position.Left} className={styles.handle} />

      <div className={styles.toolNodeContent}>
        <div className={styles.toolNodeHeader}>
          <span className={styles.toolNodeLabel}>{label}</span>
          <div className={styles.toolNodeActions}>
            {chainBroken && (
              <AlertTriangle size={12} className={styles.warningIcon} />
            )}
            <Settings size={11} className={styles.settingsIcon} onClick={handleSettingsClick} />
            <button
              type="button"
              className={`${styles.toolToggle} ${enabled ? styles.toolToggleOn : ''}`}
              onClick={handleToggle}
              aria-label={`${enabled ? 'Disable' : 'Enable'} ${label}`}
            >
              <span className={styles.toolToggleThumb} />
            </button>
          </div>
        </div>
        {badge && (
          <div className={styles.toolNodeBadges}>
            {(badge === 'active' || badge === 'both') && (
              <span className={styles.badgeActive}>Active</span>
            )}
            {(badge === 'passive' || badge === 'both') && (
              <span className={styles.badgePassive}>Passive</span>
            )}
          </div>
        )}
      </div>

      <Handle type="source" position={Position.Right} className={styles.handle} />
    </div>
  )
}

export const ToolNode = memo(ToolNodeComponent)
