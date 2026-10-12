'use client'
// Panel «Material criptográfico»: lista de tarjetas + exportación (técnica / completa).

import { useState } from 'react'
import { useLocale, useTranslations } from 'next-intl'
import { KeyRound, AlertTriangle } from 'lucide-react'
import { CyberPanel } from '@/components/cyber/CyberPanel'
import { EmptyState } from '@/components/cyber/EmptyState'
import { CryptoKeyCard } from '@/components/code-scan/crypto-key-card'
import { exportCryptoResults, triggerDownload } from '@/lib/api-client'
import type { CryptoKeysSection } from '@/lib/api-client'

export function CryptoKeysPanel({ scanId, section }: { scanId: string; section: CryptoKeysSection }) {
  const t = useTranslations('codeScanCrypto')
  const locale = useLocale()
  const [format, setFormat] = useState<'json' | 'txt'>('json')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<string | null>(null)
  const [confirmFull, setConfirmFull] = useState(false)
  const [acknowledged, setAcknowledged] = useState(false)
  const items = section.items ?? []

  async function doExport(mode: 'technical' | 'full') {
    setBusy(true)
    setMsg(null)
    const r = await exportCryptoResults(scanId, { mode, format, confirm: mode === 'full' ? true : undefined }, locale)
    setBusy(false)
    if (r.error || !r.blob) {
      setMsg(r.error?.error || t('exportError'))
      return
    }
    triggerDownload(r.blob, r.filename || `crypto-${mode}.${format}`)
    setConfirmFull(false)
    setAcknowledged(false)
  }

  return (
    <CyberPanel title={t('title')} subtitle={t('subtitle')}>
      {section.error && (
        <p className="mb-3 rounded-lg border border-yellow-500/30 bg-yellow-500/5 px-3 py-2 text-xs text-yellow-400">{section.error}</p>
      )}
      {section.warning && (
        <p className="mb-3 rounded-lg border border-yellow-500/30 bg-yellow-500/5 px-3 py-2 text-xs text-yellow-400">{section.warning}</p>
      )}

      {items.length === 0 ? (
        section.error ? (
          <EmptyState icon={AlertTriangle} title={t('failedTitle')} detail={t('failedDetail')} />
        ) : (
          <EmptyState icon={KeyRound} title={t('emptyTitle')} detail={t('emptyDetail')} />
        )
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value as 'json' | 'txt')}
              className="h-8 rounded border border-[hsl(var(--border))] bg-transparent px-2 text-xs"
              aria-label={t('exportFormat')}
            >
              <option value="json">JSON</option>
              <option value="txt">TXT</option>
            </select>
            <button type="button" disabled={busy} onClick={() => doExport('technical')} className="rounded-lg border border-[hsl(var(--border))] px-3 py-1.5 text-xs hover:bg-[hsl(var(--muted))]/40 disabled:opacity-50">
              {t('exportTechnical')}
            </button>
            <button type="button" disabled={busy} onClick={() => setConfirmFull(!confirmFull)} className="rounded-lg border border-red-500/40 px-3 py-1.5 text-xs text-red-300 hover:bg-red-500/10 disabled:opacity-50">
              {t('exportFull')}
            </button>
            <span className="text-[11px] text-muted-foreground">{t('exportTechnicalNote')}</span>
          </div>

          {confirmFull && (
            <div className="mb-3 space-y-2 rounded-lg border border-red-500/40 bg-red-500/5 p-3 text-xs">
              <p className="font-semibold text-red-300">{t('fullWarningTitle')}</p>
              <p className="text-red-200/90">{t('fullWarning')}</p>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={acknowledged} onChange={(e) => setAcknowledged(e.target.checked)} />
                {t('fullAcknowledge')}
              </label>
              <button type="button" disabled={!acknowledged || busy} onClick={() => doExport('full')} className="rounded-lg border border-red-500/60 px-3 py-1.5 text-red-200 disabled:opacity-50">
                {t('fullConfirm')}
              </button>
            </div>
          )}
          {msg && <p className="mb-3 rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-400">{msg}</p>}

          <div className="space-y-3">
            {items.map((it) => <CryptoKeyCard key={it.id} scanId={scanId} item={it} />)}
          </div>

          {section.limitations && section.limitations.length > 0 && (
            <details className="mt-4 text-xs text-muted-foreground">
              <summary className="cursor-pointer">{t('limitations')}</summary>
              <ul className="mt-2 list-disc space-y-1 pl-5">{section.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
            </details>
          )}
        </>
      )}
    </CyberPanel>
  )
}
