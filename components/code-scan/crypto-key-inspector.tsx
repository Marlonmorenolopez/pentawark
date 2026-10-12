'use client'
// Inspección completa de una llave. Los parámetros PRIVADOS solo se piden al backend cuando el
// usuario abre esta sección (y, si la llave está cifrada, escribe su contraseña). Todo queda en
// memoria del componente: nada se guarda en localStorage, historial ni URL.

import { useState } from 'react'
import { useLocale, useTranslations } from 'next-intl'
import { Loader2, Copy, Check, Eye, EyeOff, Lock, ChevronDown } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import { inspectCryptoItem } from '@/lib/api-client'
import type { CryptoInspectResponse, CryptoItem, CryptoParam } from '@/lib/api-client'
import { copyText, groupHex, hexToDecimal, paramsToText } from '@/lib/crypto-format'

function CopyButton({ text, label }: { text: string; label: string }) {
  const t = useTranslations('codeScanCrypto')
  const [state, setState] = useState<'idle' | 'ok' | 'error'>('idle')
  async function onCopy() {
    const r = await copyText(text)
    setState(r)
    setTimeout(() => setState('idle'), 2000)
  }
  return (
    <button
      type="button"
      onClick={onCopy}
      className="inline-flex items-center gap-1 rounded border border-[hsl(var(--border))] px-2 py-0.5 text-[11px] text-muted-foreground hover:text-foreground"
      aria-label={label}
    >
      {state === 'ok' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
      {state === 'ok' ? t('copied') : state === 'error' ? t('copyFailed') : label}
    </button>
  )
}

function ParamRow({ p }: { p: CryptoParam }) {
  const t = useTranslations('codeScanCrypto')
  const [dec, setDec] = useState(false)
  const isInt = p.encoding === 'integer'
  const shown = dec && isInt ? hexToDecimal(p.hex) : groupHex(p.hex)
  const isPrivate = p.kind === 'private'
  return (
    <div className={cn('rounded-lg border px-3 py-2', isPrivate ? 'border-red-500/40 bg-red-500/5' : 'border-[hsl(var(--border))]')}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-xs font-semibold">
          {p.name}
          {p.bits ? <span className="ml-2 font-normal text-muted-foreground">{p.bits} bits</span> : null}
          <span className={cn('ml-2 rounded px-1.5 py-0.5 text-[10px] uppercase', isPrivate ? 'bg-red-500/20 text-red-300' : 'bg-blue-500/20 text-blue-300')}>
            {isPrivate ? t('private') : t('public')}
          </span>
        </span>
        <span className="flex gap-1.5">
          {isInt && (
            <button type="button" onClick={() => setDec(!dec)} className="rounded border border-[hsl(var(--border))] px-2 py-0.5 text-[11px] text-muted-foreground hover:text-foreground">
              {dec ? t('showHex') : t('showDecimal')}
            </button>
          )}
          <CopyButton text={dec && isInt ? hexToDecimal(p.hex) : p.hex} label={t('copy')} />
        </span>
      </div>
      <p className="mt-1.5 max-h-40 overflow-y-auto break-all whitespace-pre-wrap font-mono text-[11px] text-foreground">{shown}</p>
    </div>
  )
}

export function CryptoKeyInspector({ scanId, item }: { scanId: string; item: CryptoItem }) {
  const t = useTranslations('codeScanCrypto')
  const locale = useLocale()
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [data, setData] = useState<CryptoInspectResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)

  const needsPassword = item.status === 'needs_password' || data?.status === 'needs_password'
  const wrongPassword = data?.detail_code === 'wrong_password'

  async function load(pw?: string) {
    setLoading(true)
    setError(null)
    const res = await inspectCryptoItem(scanId, item.id, pw || undefined, locale)
    setLoading(false)
    if (res.error || !res.data) {
      setData(null)
      setError(res.error?.error || t('inspectError'))
      return
    }
    setData(res.data)
  }

  function toggle() {
    const next = !open
    setOpen(next)
    if (!next) {            // al cerrar se descartan los valores y la contraseña de la memoria
      setData(null)
      setPassword('')
      setError(null)
      return
    }
    if (!needsPassword) void load()
  }

  const all = data ? [...data.public_params, ...data.private_params] : []

  return (
    <div className="mt-3">
      <button
        type="button"
        onClick={toggle}
        disabled={!item.inspectable}
        aria-expanded={open}
        className="inline-flex items-center gap-1.5 rounded-lg border border-[hsl(var(--border))] px-3 py-1.5 text-xs font-medium hover:bg-[hsl(var(--muted))]/40 disabled:cursor-not-allowed disabled:opacity-50"
      >
        <ChevronDown className={cn('h-3.5 w-3.5 transition-transform', open && 'rotate-180')} />
        {t('inspect')}
      </button>
      {!item.inspectable && <p className="mt-1 text-[11px] text-muted-foreground">{t('notInspectable')}</p>}

      {open && (
        <div className="mt-3 space-y-3">
          {needsPassword && !(data && data.status !== 'needs_password') && (
            <form
              onSubmit={(e) => { e.preventDefault(); if (password) void load(password) }}
              className="space-y-2 rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-3"
            >
              <p className="flex items-center gap-1.5 text-xs text-yellow-400"><Lock className="h-3.5 w-3.5" />{t('passwordRequired')}</p>
              <div className="flex gap-2">
                <Input
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="off"
                  placeholder={t('passwordPlaceholder')}
                  className="h-8 font-mono text-xs"
                />
                <button type="button" onClick={() => setShowPw(!showPw)} className="rounded border border-[hsl(var(--border))] px-2" aria-label={showPw ? t('hide') : t('show')}>
                  {showPw ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </button>
                <button type="submit" disabled={!password || loading} className="rounded border border-[hsl(var(--border))] px-3 text-xs disabled:opacity-50">{t('decrypt')}</button>
              </div>
              <p className="text-[11px] text-muted-foreground">{t('passwordNote')}</p>
              {wrongPassword && <p className="text-xs text-red-400">{t('wrongPassword')}</p>}
            </form>
          )}

          {loading && <p className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" />{t('loading')}</p>}
          {error && <p className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-400">{error}</p>}

          {data && data.status !== 'needs_password' && (
            <>
              {all.length === 0 ? (
                <p className="text-xs text-muted-foreground">{t('noParams')}</p>
              ) : (
                <>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-xs text-muted-foreground">{t('fullValuesNote')}</p>
                    <CopyButton text={paramsToText(all)} label={t('copyAll')} />
                  </div>
                  {data.private_params.length > 0 && (
                    <p className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-300">{t('privateWarning')}</p>
                  )}
                  <div className="space-y-2">
                    {data.public_params.length > 0 && <h5 className="text-xs font-semibold uppercase text-blue-300">{t('publicParams')}</h5>}
                    {data.public_params.map((p) => <ParamRow key={'pub-' + p.name} p={p} />)}
                    {data.private_params.length > 0 && <h5 className="pt-1 text-xs font-semibold uppercase text-red-300">{t('privateParams')}</h5>}
                    {data.private_params.map((p) => <ParamRow key={'prv-' + p.name} p={p} />)}
                  </div>
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
