// lib/crypto-format.ts — utilidades de presentación para parámetros criptográficos.
// Solo formatean valores ya recibidos; no hacen peticiones ni guardan nada.

/** Agrupa un hex en pares separados por ':' (a1:b2:c3...). */
export function groupHex(hex: string): string {
  const clean = (hex || '').replace(/[^0-9a-fA-F]/g, '')
  return (clean.match(/.{1,2}/g) || []).join(':')
}

/** Hex -> decimal (BigInt). Devuelve '' si el valor no es un entero válido. */
export function hexToDecimal(hex: string): string {
  const clean = (hex || '').replace(/[^0-9a-fA-F]/g, '')
  if (!clean) return ''
  try {
    return BigInt('0x' + clean).toString(10)
  } catch {
    return ''
  }
}

export type CopyResult = 'ok' | 'error'

/** Copia al portapapeles con respaldo a execCommand. Nunca lanza: devuelve 'error' si falla. */
export async function copyText(text: string): Promise<CopyResult> {
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return 'ok'
    }
  } catch {
    // cae al respaldo
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.setAttribute('readonly', '')
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok ? 'ok' : 'error'
  } catch {
    return 'error'
  }
}

/** Texto con todos los parámetros (para «copiar todos»). Valores completos, sin truncar. */
export function paramsToText(params: { name: string; hex: string; bits: number | null }[]): string {
  return params
    .map((p) => `${p.name}${p.bits ? ` (${p.bits} bits)` : ''}:\n${p.hex}`)
    .join('\n\n')
}
