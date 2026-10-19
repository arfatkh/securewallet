// Money is integer paisa end to end. These helpers never go through floats
// for parsing, so "0.1 + 0.2" style errors can't reach the API.

export function rupees(paisa, { sign = false } = {}) {
  const neg = paisa < 0
  const abs = Math.abs(paisa)
  const whole = Math.floor(abs / 100).toLocaleString('en-PK')
  const frac = String(abs % 100).padStart(2, '0')
  const s = sign ? (neg ? '− ' : '+ ') : (neg ? '−' : '')
  return { text: `${s}Rs ${whole}.${frac}`, whole, frac, neg }
}

export const rs = (paisa, opts) => rupees(paisa, opts).text

// "2,000.5" -> 200050. Returns null for anything that isn't a clean amount.
export function parseRupees(input) {
  const s = String(input).replace(/,/g, '').trim()
  if (!/^\d{1,9}(\.\d{0,2})?$/.test(s)) return null
  const [w, f = ''] = s.split('.')
  return Number(w) * 100 + Number((f + '00').slice(0, 2))
}

export function initials(name = '') {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  return ((parts[0]?.[0] || '') + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase() || '?'
}

const TINTS = ['jade', 'saffron', 'sky', 'rose', 'lilac', 'sand']
export function tint(seed = '') {
  let h = 0
  for (const c of seed) h = (h * 31 + c.charCodeAt(0)) >>> 0
  return TINTS[h % TINTS.length]
}

export function dayLabel(iso) {
  const d = new Date(iso)
  const today = new Date(); today.setHours(0, 0, 0, 0)
  const that = new Date(d); that.setHours(0, 0, 0, 0)
  const diff = Math.round((today - that) / 86400000)
  if (diff === 0) return 'Today'
  if (diff === 1) return 'Yesterday'
  return d.toLocaleDateString('en-GB', { weekday: diff < 7 ? 'long' : undefined, day: 'numeric', month: 'long' })
}

export const time = iso => new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
export const dateTime = iso => new Date(iso).toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })

// Amount in words in the Pakistani (South Asian) system, as printed on cheques:
// 24770050 paisa -> "Two lakh forty-seven thousand seven hundred rupees and fifty paisa only".
const ONES = ['', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve',
              'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen']
const TENS = ['', '', 'twenty', 'thirty', 'forty', 'fifty', 'sixty', 'seventy', 'eighty', 'ninety']
const twoDigits = n => (n < 20 ? ONES[n] : TENS[Math.floor(n / 10)] + (n % 10 ? '-' + ONES[n % 10] : ''))
function wordsBelowThousand(n) {
  const h = Math.floor(n / 100), r = n % 100
  return [h ? `${ONES[h]} hundred` : '', r ? twoDigits(r) : ''].filter(Boolean).join(' ')
}
function integerWords(n) {
  if (n === 0) return 'zero'
  const parts = []
  for (const [size, name] of [[1e7, 'crore'], [1e5, 'lakh'], [1e3, 'thousand']]) {
    const q = Math.floor(n / size)
    if (q) { parts.push(`${integerWords(q)} ${name}`); n %= size }
  }
  if (n) parts.push(wordsBelowThousand(n))
  return parts.join(' ')
}
export function amountInWords(paisa) {
  if (paisa == null || !Number.isFinite(paisa)) return ''
  const neg = paisa < 0
  const abs = Math.abs(Math.round(paisa))
  const r = Math.floor(abs / 100), p = abs % 100
  let s = r || !p ? `${integerWords(r)} rupee${r === 1 ? '' : 's'}` : ''
  if (p) s += `${s ? ' and ' : ''}${twoDigits(p)} paisa`
  s = s.charAt(0).toUpperCase() + s.slice(1) + ' only'
  return neg ? `Minus ${s.charAt(0).toLowerCase()}${s.slice(1)}` : s
}
