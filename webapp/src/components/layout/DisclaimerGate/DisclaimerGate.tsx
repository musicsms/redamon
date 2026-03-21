'use client'

import { useState, useEffect, useCallback } from 'react'
import { ShieldAlert, ExternalLink } from 'lucide-react'
import {
  DISCLAIMER_VERSION,
  DISCLAIMER_STORAGE_KEY,
  DISCLAIMER_GITHUB_URL,
} from '@/lib/disclaimerVersion'
import styles from './DisclaimerGate.module.css'

interface DisclaimerGateProps {
  children: React.ReactNode
}

interface StoredAcceptance {
  version: string
  acceptedAt: string
}

const CHECKBOXES = [
  {
    id: 'authorization',
    label:
      'I confirm I have explicit written authorization to test target systems and understand unauthorized access is illegal under CFAA, Computer Misuse Act, and equivalent laws.',
  },
  {
    id: 'liability',
    label:
      'I acknowledge this software is provided "AS IS" with no warranty. Authors and contributors bear no liability for any damages, data loss, or legal consequences.',
  },
  {
    id: 'data-privacy',
    label:
      'I understand that reconnaissance data, credentials, and vulnerability details are transmitted to external LLM providers (OpenAI, Anthropic, etc.) and third-party services with no privacy guarantee.',
  },
  {
    id: 'data-persistence',
    label:
      'I understand all data is stored indefinitely in Neo4j/PostgreSQL with no automatic deletion. I am responsible for cleanup after engagements.',
  },
  {
    id: 'ai-agent',
    label:
      'I understand the AI agent operates autonomously and may take unexpected actions including scope drift, service degradation, or unintended exploitation. Approval gates are best-effort safeguards.',
  },
  {
    id: 'third-party',
    label:
      'I understand I must comply with licenses of all bundled tools (AGPL-3.0, GPL, MIT, etc.) and applicable regulations including export controls.',
  },
] as const

export function DisclaimerGate({ children }: DisclaimerGateProps) {
  const [isLoading, setIsLoading] = useState(true)
  const [isAccepted, setIsAccepted] = useState(false)
  const [checked, setChecked] = useState<boolean[]>(
    () => new Array(CHECKBOXES.length).fill(false)
  )

  useEffect(() => {
    try {
      const stored = localStorage.getItem(DISCLAIMER_STORAGE_KEY)
      if (stored) {
        const parsed: StoredAcceptance = JSON.parse(stored)
        if (parsed.version === DISCLAIMER_VERSION) {
          setIsAccepted(true)
        }
      }
    } catch {
      // localStorage unavailable or corrupted — show the gate
    }
    setIsLoading(false)
  }, [])

  const handleToggle = useCallback((index: number) => {
    setChecked((prev) => {
      const next = [...prev]
      next[index] = !next[index]
      return next
    })
  }, [])

  const handleAccept = useCallback(() => {
    try {
      const value: StoredAcceptance = {
        version: DISCLAIMER_VERSION,
        acceptedAt: new Date().toISOString(),
      }
      localStorage.setItem(DISCLAIMER_STORAGE_KEY, JSON.stringify(value))
    } catch {
      // localStorage unavailable — acceptance lasts this session only
    }
    setIsAccepted(true)
  }, [])

  const allChecked = checked.every(Boolean)

  if (isLoading) {
    return null
  }

  if (isAccepted) {
    return <>{children}</>
  }

  return (
    <div className={styles.overlay}>
      <div className={styles.card}>
        <div className={styles.header}>
          <div className={styles.headerLeft}>
            <ShieldAlert size={22} className={styles.headerIcon} />
            <h1 className={styles.title}>Legal Disclaimer & Terms of Use</h1>
          </div>
        </div>

        <div className={styles.body}>
          <p className={styles.intro}>
            <strong>RedAmon</strong> is an AI-powered penetration testing
            platform intended exclusively for{' '}
            <strong>authorized security testing</strong>,{' '}
            <strong>educational purposes</strong>, and{' '}
            <strong>research</strong>. Before using this tool, you must read and
            accept the following terms.
          </p>

          <div className={styles.linkWrapper}>
            <a
              href={DISCLAIMER_GITHUB_URL}
              target="_blank"
              rel="noopener noreferrer"
              className={styles.fullDisclaimerLink}
            >
              Read the full legal disclaimer
              <ExternalLink size={13} />
            </a>
          </div>

          <div className={styles.checkboxList}>
            {CHECKBOXES.map((item, index) => (
              <label key={item.id} className={styles.checkboxRow}>
                <input
                  type="checkbox"
                  checked={checked[index]}
                  onChange={() => handleToggle(index)}
                  className={styles.checkbox}
                />
                <span className={styles.checkboxLabel}>{item.label}</span>
              </label>
            ))}
          </div>
        </div>

        <div className={styles.footer}>
          <button
            className={styles.acceptButton}
            disabled={!allChecked}
            onClick={handleAccept}
          >
            I Accept All Terms
          </button>
        </div>
      </div>
    </div>
  )
}
