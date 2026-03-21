'use client'

import { Scale } from 'lucide-react'
import { DISCLAIMER_GITHUB_URL } from '@/lib/disclaimerVersion'
import styles from './Footer.module.css'

export function Footer() {
  const currentYear = new Date().getFullYear()

  return (
    <footer className={styles.footer}>
      <div className={styles.content}>
        <div className={styles.left}>
          <span className={styles.copyright}>
            © {currentYear} RedAmon. All rights reserved.
          </span>
          <a
            href={DISCLAIMER_GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            className={styles.legalLink}
          >
            <Scale size={12} />
            Legal & Terms of Use
          </a>
        </div>
        <span className={styles.version}>v2.3.0</span>
      </div>
    </footer>
  )
}
