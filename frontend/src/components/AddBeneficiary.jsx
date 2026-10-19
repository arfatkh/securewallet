import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api.js'
import { traceStore } from '../trace.js'
import { Banner } from './Bits.jsx'
import * as Icon from './Icons.jsx'

// Adding a saved payee is authorised with the transaction PIN, like a transfer:
// a stolen or unattended session must not be able to plant a mule account (W11).
export default function AddBeneficiary({ initialUsername = '', onAdded, onClose }) {
  const [username, setUsername] = useState(initialUsername)
  const [nickname, setNickname] = useState('')
  const [pin, setPin] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const submit = async e => {
    e.preventDefault()
    const u = username.trim().replace(/^@/, '').toLowerCase()
    setBusy(true); setError(null)
    traceStore.beginFlow(`Add beneficiary @${u}`, 'payee')
    try {
      const b = await api('/beneficiaries', {
        method: 'POST', label: 'Add beneficiary',
        body: { username: u, nickname: nickname.trim() || undefined, tpin: pin },
      })
      onAdded?.(b)
    } catch (err) {
      setError({ text: err.message, code: err.data?.code })
    } finally {
      setPin('')
      setBusy(false)
    }
  }

  return (
    <div className="modal-scrim" onMouseDown={e => e.target === e.currentTarget && !busy && onClose()}>
      <form className="modal benef" role="dialog" aria-modal="true" aria-labelledby="benef-h" onSubmit={submit}>
        <div>
          <p className="pb-label">Saved payees</p>
          <h2 id="benef-h">Add a beneficiary</h2>
          <p className="muted" style={{ fontSize: 14 }}>Saved payees appear on Home and at the top of Send money. Adding one needs your transaction PIN.</p>
        </div>
        <label className="pb-field benef-field" htmlFor="benef-user">
          <span>Username</span>
          <span className="benef-at"><b>@</b><input id="benef-user" value={username} autoFocus={!initialUsername}
            onChange={e => setUsername(e.target.value)} autoCapitalize="none" spellCheck="false" autoComplete="off" required /></span>
        </label>
        <label className="pb-field benef-field" htmlFor="benef-nick">
          <span>Nickname <i>(optional)</i></span>
          <input id="benef-nick" value={nickname} maxLength={40} onChange={e => setNickname(e.target.value)} placeholder="e.g. Rent, Cricket team" />
        </label>
        <label className="pb-field benef-field" htmlFor="benef-pin">
          <span><Icon.Lock size={12} /> Transaction PIN</span>
          <input id="benef-pin" className="mono benef-pin" type="password" inputMode="numeric" autoComplete="off"
                 autoFocus={!!initialUsername} maxLength={6} value={pin} disabled={error?.code === 'tpin_locked'}
                 onChange={e => setPin(e.target.value.replace(/\D/g, '').slice(0, 6))} aria-describedby="benef-pin-help" />
        </label>
        <p id="benef-pin-help" className="pb-hint">The same 6-digit PIN you use to send money. Three wrong tries lock it for 15 minutes.</p>
        {error && (
          <Banner kind={error.code === 'tpin_locked' ? 'warn' : 'error'}>
            {error.text}{' '}
            {error.code === 'tpin_required' && <Link to="/security" onClick={onClose}>Set a PIN in Security</Link>}
          </Banner>
        )}
        <div className="benef-actions">
          <button type="button" className="btn quiet" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="btn primary" disabled={busy || !username.trim() || pin.length !== 6 || error?.code === 'tpin_locked'}>
            {busy ? 'Adding…' : 'Add beneficiary'}
          </button>
        </div>
      </form>
    </div>
  )
}
