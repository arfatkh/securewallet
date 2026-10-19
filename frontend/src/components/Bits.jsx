import { initials, rupees, tint } from '../format.js'
import * as Icon from './Icons.jsx'

export function Avatar({ name, seed, size = 40 }) {
  return (
    <span className={`avatar ${tint(seed || name)}`} style={{ width: size, height: size, fontSize: size * 0.36 }}>
      {initials(name)}
    </span>
  )
}

export function Money({ paisa, sign, className = '' }) {
  const m = rupees(paisa, { sign })
  return <span className={`num ${className}`}>{m.text}</span>
}

export function Banner({ kind = 'error', children }) {
  const Ico = kind === 'ok' ? Icon.Check : kind === 'warn' ? Icon.Alert : Icon.Info
  return <div className={`banner ${kind}`} role={kind === 'error' ? 'alert' : 'status'}><Ico size={18} /><div>{children}</div></div>
}

export function StatusPill({ status, reason }) {
  if (status === 'completed') return null
  if (status === 'failed') return <span className="pill bad">Failed{reason ? ` · ${reason}` : ''}</span>
  if (status === 'awaiting_passkey') return <span className="pill warn">Awaiting approval</span>
  return <span className="pill neutral">{status}</span>
}
