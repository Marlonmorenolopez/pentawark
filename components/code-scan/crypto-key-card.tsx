'use client'
// Tarjeta de un hallazgo criptográfico: SOLO metadatos públicos. Los parámetros se piden bajo
// demanda desde «Inspeccionar llave» (CryptoKeyInspector).

import { useTranslations } from 'next-intl'
import { FileKey, ShieldAlert } from 'lucide-react'
import { CyberBadge } from '@/components/cyber/CyberBadge'
import type { CryptoItem } from '@/lib/api-client'
import { CryptoKeyInspector } from '@/components/code-scan/crypto-key-inspector'

function sev(s: string | null): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  return s === 'critical' || s === 'high' || s === 'medium' || s === 'low' ? s : 'info'
}

function Field({ label, value }: { label: string; value?: string | number | null }) {
  if (value === null || value === undefined || value === '') return null
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase text-muted-foreground">{label}</dt>
      <dd className="break-all font-mono text-xs">{value}</dd>
    </div>
  )
}

export function CryptoKeyCard({ scanId, item }: { scanId: string; item: CryptoItem }) {
  const t = useTranslations('codeScanCrypto')
  const label = (group: string, key?: string | null) => (key ? (t.has(`${group}.${key}`) ? t(`${group}.${key}`) : key) : null)
  const methods = Array.from(new Set(item.tools.filter((x) => x.operation).map((x) => x.operation as string)))

  return (
    <div className="rounded-lg border border-[hsl(var(--border))] px-3 py-3 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex min-w-0 items-center gap-2 font-mono text-xs font-semibold">
          <FileKey className="h-4 w-4 shrink-0 text-[var(--cyber-accent)]" />
          <span className="break-all">{item.name}</span>
        </span>
        <CyberBadge type={sev(item.risk)} size="sm" />
      </div>
      <p className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{item.file}{item.line ? `:${item.line}` : ''}</p>

      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-3 lg:grid-cols-4">
        <Field label={t('f.type')} value={label('types', item.material_type)} />
        <Field label={t('f.algorithm')} value={item.algorithm} />
        <Field label={t('f.size')} value={item.key_size ? `${item.key_size} bits` : null} />
        <Field label={t('f.curve')} value={item.curve} />
        <Field label={t('f.format')} value={[item.format, item.encoding].filter(Boolean).join(' · ')} />
        <Field label={t('f.status')} value={label('statuses', item.status)} />
        <Field label={t('f.protection')} value={label('protection', item.protection)} />
        <Field label={t('f.cipher')} value={item.cipher} />
        <Field label={t('f.context')} value={label('context', item.context)} />
        <Field label={t('f.fingerprint')} value={item.fingerprint} />
        {item.cert && (
          <>
            <Field label={t('f.subject')} value={item.cert.subject} />
            <Field label={t('f.issuer')} value={item.cert.issuer} />
            <Field label={t('f.notAfter')} value={item.cert.not_after} />
            <Field label={t('f.signature')} value={item.cert.signature_algorithm} />
          </>
        )}
      </dl>

      <p className="mt-3 text-[11px] text-muted-foreground">
        {t('f.tools')}: {item.tools.map((x) => `${x.tool}${x.version ? ' ' + x.version : ''}`).filter((v, i, a) => a.indexOf(v) === i).join(', ')}
        {methods.length > 0 && <> · {t('f.methods')}: {methods.join(', ')}</>}
      </p>

      {item.weaknesses.length > 0 && (
        <ul className="mt-3 space-y-2">
          {item.weaknesses.map((w) => (
            <li key={w.code} className="rounded-lg bg-[hsl(var(--muted))]/40 px-3 py-2 text-xs">
              <p className="flex flex-wrap items-center gap-2 font-semibold">
                <ShieldAlert className="h-3.5 w-3.5" />
                {w.title}
                <span className="rounded bg-[hsl(var(--muted))] px-1.5 py-0.5 text-[10px] font-normal uppercase">{label('kinds', w.kind)}</span>
              </p>
              <p className="mt-1 text-muted-foreground">{w.description}</p>
              <p className="mt-1">→ {w.recommendation}</p>
            </li>
          ))}
        </ul>
      )}

      <CryptoKeyInspector scanId={scanId} item={item} />
    </div>
  )
}
