import { useMemo } from 'react'

// Banknote guilloche: stacked hypotrochoid rosettes, the same interference
// pattern printed on currency to make it hard to reproduce.
function rosette(R, r, d, steps, cx, cy) {
  const pts = []
  const k = (R - r) / r
  const turns = r / gcd(R, r)
  for (let i = 0; i <= steps; i++) {
    const t = (i / steps) * Math.PI * 2 * turns
    const x = cx + (R - r) * Math.cos(t) + d * Math.cos(k * t)
    const y = cy + (R - r) * Math.sin(t) - d * Math.sin(k * t)
    pts.push(`${x.toFixed(1)},${y.toFixed(1)}`)
  }
  return 'M' + pts.join('L')
}
function gcd(a, b) { return b ? gcd(b, a % b) : a }

// Engraved line field: many fine sine hairlines whose phase drifts, giving the
// moiré "security print" texture used on statements and cheques.
function waveField(count, w, h) {
  const out = []
  for (let i = 0; i < count; i++) {
    const y0 = (h / (count - 1)) * i
    const amp = 6 + 5 * Math.sin(i / 3.1)
    const ph = i * 0.21
    const pts = []
    for (let x = 0; x <= w; x += 6) {
      const y = y0 + amp * Math.sin(x / 38 + ph) + 2.2 * Math.sin(x / 11 - ph * 2)
      pts.push(`${x},${y.toFixed(1)}`)
    }
    out.push('M' + pts.join('L'))
  }
  return out
}

export default function Guilloche({ className = '', layers = 5, variant = 'rosette' }) {
  const paths = useMemo(() => {
    if (variant === 'waves') return waveField(layers, 400, 400)
    const out = []
    for (let i = 0; i < layers; i++) out.push(rosette(96 + i * 4, 23 + (i % 2), 52 + i * 9, 1400, 200, 200))
    out.push(rosette(160, 37, 30, 1600, 200, 200))
    return out
  }, [layers, variant])

  if (variant === 'waves') {
    return (
      <svg className={`guilloche waves ${className}`} viewBox="0 0 400 400" preserveAspectRatio="none" aria-hidden="true">
        {paths.map((d, i) => (
          <path key={i} d={d} fill="none" stroke="currentColor" strokeWidth="0.5" vectorEffect="non-scaling-stroke" />
        ))}
      </svg>
    )
  }

  return (
    <svg className={`guilloche ${className}`} viewBox="0 0 400 400" aria-hidden="true">
      {paths.map((d, i) => (
        <path key={i} d={d} fill="none" stroke="currentColor" strokeWidth={i === paths.length - 1 ? 0.5 : 0.6}
              opacity={1 - i * 0.1} />
      ))}
      <circle cx="200" cy="200" r="186" fill="none" stroke="currentColor" strokeWidth="0.6" strokeDasharray="1.5 3" />
    </svg>
  )
}
