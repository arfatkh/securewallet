import { useEffect, useState } from 'react'
import { api } from '../api.js'
import { Banner } from '../components/Bits.jsx'
import * as Icon from '../components/Icons.jsx'
import { dateTime } from '../format.js'
import { useSession } from '../session.jsx'
import { traceStore } from '../trace.js'
import { createPasskey, passkeysSupported } from '../webauthn.js'
import './Security.css'

function guessDevice() {
  const ua = navigator.userAgent
  if (/iPhone|iPad/.test(ua)) return 'iPhone'
  if (/Android/.test(ua)) return 'Android phone'
  if (/Mac/.test(ua)) return 'Mac'
  if (/Windows/.test(ua)) return 'Windows Hello'
  return 'This device'
}

// Mirrors the server's weak-PIN rules (security/tpin.py) so the hint shows before submitting.
// The server is still the one that decides.
const COMMON_PINS = new Set(['000000', '111111', '121212', '112233', '123123', '123321', '131313', '159753', '147258',
  '147852', '142536', '159357', '112211', '101010', '202020', '696969', '777777', '520520', '007007', '786786'])
const isRun = (pin, step) => [...pin].slice(1).every((d, i) => ((Number(d) - Number(pin[i])) % 10 + 10) % 10 === (step + 10) % 10)
function weakPin(pin) {
  if (!/^\d{6}$/.test(pin)) return 'Use exactly 6 digits.'
  if (new Set(pin).size === 1) return "Don't repeat one digit."
  if (isRun(pin, 1) || isRun(pin, -1)) return "Don't use digits in sequence like 123456 or 654321."
  if (COMMON_PINS.has(pin) || pin.slice(0, 3) === pin.slice(3) || pin.slice(0, 2).repeat(3) === pin) return 'This PIN is too common. Pick something harder to guess.'
  return ''
}
const digits = v => v.replace(/\D/g, '').slice(0, 6)

function PinCard({ hasPin, onSaved }) {
  const [open, setOpen] = useState(!hasPin)
  const [password, setPassword] = useState('')
  const [pin, setPin] = useState('')
  const [pin2, setPin2] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState(null)

  const weak = pin.length === 6 ? weakPin(pin) : ''
  const mismatch = pin2.length === 6 && pin !== pin2 ? "The PINs don't match." : ''
  const ready = password && pin.length === 6 && !weak && pin === pin2

  const save = async e => {
    e.preventDefault()
    if (!ready) return
    setBusy(true); setMsg(null)
    traceStore.beginFlow(hasPin ? 'Change transaction PIN' : 'Set transaction PIN', 'action')
    try {
      await api('/tpin', { method: 'POST', body: { password, new_pin: pin }, label: 'Save transaction PIN' })
      setMsg(['ok', hasPin ? 'Transaction PIN changed.' : 'Transaction PIN set. You can now send money.'])
      setPassword(''); setPin(''); setPin2(''); setOpen(false)
      onSaved()
    } catch (err) { setMsg(['error', err.message]) } finally { setBusy(false) }
  }

  return (
    <section className="pb-sheet sec-sheet" aria-labelledby="sec-tpin">
      <header className="pb-sheet-head">
        <h2 id="sec-tpin"><span className="sec-no">I.</span>Transaction PIN</h2>
        <span className={`pb-flag ${hasPin ? 'ok' : 'warn'}`}>{hasPin ? 'Set' : 'Required'}</span>
      </header>
      <p className="sec-lede">
        A 6-digit PIN you enter every time you send money. Someone who gets into your session still can't
        pay anyone without it. Three wrong entries lock transfers for 15 minutes.
      </p>
      <div className="sec-body">
        {msg && <Banner kind={msg[0]}>{msg[1]}</Banner>}
        {!hasPin && !msg && <Banner kind="warn">Set a transaction PIN before you can send money.</Banner>}
        {!open ? (
          <div className="sec-actions">
            <button className="btn" onClick={() => { setOpen(true); setMsg(null) }}><Icon.Key size={18} />Change PIN</button>
          </div>
        ) : (
          <form className="sec-form" onSubmit={save} autoComplete="off">
            <div className="sec-line">
              <label htmlFor="tpin-pw">Account password</label>
              <input id="tpin-pw" className="input" type="password" autoComplete="current-password" value={password}
                     onChange={e => setPassword(e.target.value)} />
              <p className="pb-hint">We ask again so a session left open can't change your PIN.</p>
            </div>
            <div className="sec-pin-row">
              <div className="sec-line">
                <label htmlFor="tpin-new">{hasPin ? 'New PIN' : 'PIN'}</label>
                <input id="tpin-new" className="input sec-pin" type="password" inputMode="numeric" autoComplete="off"
                       maxLength={6} pattern="\d{6}" placeholder="••••••" value={pin} aria-invalid={!!weak}
                       onChange={e => setPin(digits(e.target.value))} />
              </div>
              <div className="sec-line">
                <label htmlFor="tpin-confirm">Confirm PIN</label>
                <input id="tpin-confirm" className="input sec-pin" type="password" inputMode="numeric" autoComplete="off"
                       maxLength={6} pattern="\d{6}" placeholder="••••••" value={pin2} aria-invalid={!!mismatch}
                       onChange={e => setPin2(digits(e.target.value))} />
              </div>
            </div>
            {weak ? <p className="error">{weak}</p> : mismatch ? <p className="error">{mismatch}</p>
              : <p className="hint">Avoid birthdays, repeated digits and runs like 123456.</p>}
            <div className="sec-actions">
              <button className="btn primary" disabled={!ready || busy}>
                <Icon.Check size={18} />{busy ? 'Saving…' : hasPin ? 'Change PIN' : 'Set PIN'}
              </button>
              {hasPin && <button type="button" className="btn quiet" onClick={() => { setOpen(false); setPassword(''); setPin(''); setPin2('') }}>Cancel</button>}
            </div>
          </form>
        )}
      </div>
    </section>
  )
}

// Same endorsement seal as Home: a double ring when active, a dashed empty ring when not.
function Seal({ ok, title, detail, icon: Ico }) {
  return (
    <li className={`sec-seal ${ok ? 'ok' : 'todo'}`}>
      <span className="sec-seal-mark" aria-hidden="true"><Ico size={20} /></span>
      <span className="sec-seal-text">
        <b>{title}</b>
        <span>{detail}</span>
      </span>
      <span className="sec-seal-state">{ok ? 'Active' : 'Not set'}</span>
    </li>
  )
}

export default function Security() {
  const { me, reload, signOut, config } = useSession()
  const [keys, setKeys] = useState(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState(null)
  const [confirmAll, setConfirmAll] = useState(false)

  const load = () => api('/passkeys').then(d => setKeys(d.items)).catch(() => setKeys([]))
  useEffect(() => { load() }, [])

  const add = async () => {
    setBusy(true); setMsg(null)
    traceStore.beginFlow('Add a passkey', 'passkey')
    try {
      const options = await api('/passkeys/register/options', { method: 'POST', label: 'Passkey options' })
      const credential = await createPasskey(options)
      await api('/passkeys/register/verify', { method: 'POST', body: { credential, nickname: guessDevice() }, label: 'Save passkey' })
      setMsg(['ok', 'Passkey added. You can now approve large transfers with it.'])
      load(); reload().catch(() => {})
    } catch (e) { setMsg(['error', e.message]) } finally { setBusy(false) }
  }

  const remove = async id => {
    traceStore.beginFlow('Remove a passkey', 'passkey')
    try { await api(`/passkeys/${id}`, { method: 'DELETE' }); load(); reload().catch(() => {}) } catch (e) { setMsg(['error', e.message]) }
  }

  const idleMin = Math.max(1, Math.round((config.session?.idle_seconds || 300) / 60))
  const keyCount = keys === null ? me.passkeys : keys.length

  return (
    <div className="page sec">
      {/* ------------------------------------------------ endorsements */}
      <section className="pb-sheet sec-endorse" aria-labelledby="sec-endorse-h">
        <header className="pb-sheet-head">
          <h2 id="sec-endorse-h">Endorsements</h2>
          <span className="pb-hint">What protects <span className="mono">@{me.user.username}</span> right now.</span>
        </header>
        <ul className="sec-seals">
          <Seal ok title="Password" detail="Stored only as an argon2id hash" icon={Icon.Lock} />
          <Seal ok={!!me.has_tpin} title="Transaction PIN" detail={me.has_tpin ? 'Required on every payment' : 'Needed before you can send'} icon={Icon.Key} />
          <Seal ok={keyCount > 0} title="Passkey" detail={keyCount > 0 ? `${keyCount} device${keyCount > 1 ? 's' : ''} for large payments` : 'Needed for payments over Rs 50,000'} icon={Icon.Fingerprint} />
          <Seal ok title="Session guard" detail={`Signs out after ${idleMin} min without activity`} icon={Icon.Clock} />
        </ul>
      </section>

      <div className="sec-grid">
        <div className="sec-main">
          <PinCard hasPin={!!me.has_tpin} onSaved={() => reload().catch(() => {})} />

          {/* ------------------------------------------------ passkeys */}
          <section className="pb-sheet sec-sheet" aria-labelledby="sec-passkeys">
            <header className="pb-sheet-head">
              <h2 id="sec-passkeys"><span className="sec-no">II.</span>Passkeys</h2>
              <span className={`pb-flag ${keys && keys.length ? 'ok' : 'warn'}`}>
                {keys === null ? '…' : keys.length ? `${keys.length} active` : 'None yet'}
              </span>
            </header>
            <p className="sec-lede">
              A passkey lives on your phone or computer and is unlocked with your fingerprint, face or PIN.
              We only store its public half, so there is nothing here for anyone to steal or phish.
            </p>
            <div className="sec-body">
              {msg && <Banner kind={msg[0]}>{msg[1]}</Banner>}
              {keys === null ? <p className="muted">Loading…</p> : keys.length === 0 ? (
                <div className="sec-empty">
                  No passkeys yet. Transfers above Rs 50,000 will need one.
                </div>
              ) : (
                <ol className="sec-keys">
                  {keys.map((k, i) => (
                    <li key={k.id} className="sec-key">
                      <span className="sec-key-no mono" aria-hidden="true">{String(i + 1).padStart(2, '0')}</span>
                      <span className="sec-key-text">
                        <span className="sec-key-name">{k.nickname}</span>
                        <span className="sec-key-meta">
                          <span>Added <span className="mono">{dateTime(k.created_at)}</span></span>
                          {k.last_used_at && <span>Last used <span className="mono">{dateTime(k.last_used_at)}</span></span>}
                        </span>
                      </span>
                      <button className="btn sm danger quiet" onClick={() => remove(k.id)}>Remove</button>
                    </li>
                  ))}
                </ol>
              )}
              <div className="sec-actions">
                <button className="btn primary" onClick={add} disabled={busy || !passkeysSupported()}>
                  <Icon.Plus size={18} />{busy ? 'Follow your device\'s prompt…' : 'Add a passkey'}
                </button>
                {!passkeysSupported() && <p className="hint">This browser doesn't support passkeys.</p>}
              </div>
            </div>
          </section>

          {/* ------------------------------------------------ sessions */}
          <section className="pb-sheet sec-sheet" aria-labelledby="sec-sessions">
            <header className="pb-sheet-head">
              <h2 id="sec-sessions"><span className="sec-no">III.</span>Sessions</h2>
            </header>
            <div className="sec-fields">
              <div className="pb-field"><span>Signed in as</span><b className="mono">@{me.user.username}</b></div>
              <div className="pb-field"><span>Idle sign-out</span><b>After {idleMin} min</b></div>
              <div className="pb-field"><span>Session ends</span><b>After 7 days away</b></div>
            </div>
            <p className="sec-lede">
              Sessions refresh quietly while you use the app and end after 7 days away.
              If you think someone else has access, sign out everywhere.
            </p>
            <div className="sec-body">
              {!confirmAll ? (
                <div className="sec-actions">
                  <button className="btn danger" onClick={() => setConfirmAll(true)}><Icon.Out size={18} />Sign out of all devices</button>
                </div>
              ) : (
                <div className="banner warn sec-confirm">
                  <span className="sec-confirm-text">This signs you out here and on every other device.</span>
                  <div className="sec-confirm-btns">
                    <button className="btn sm" onClick={() => setConfirmAll(false)}>Keep me signed in</button>
                    <button className="btn sm primary" onClick={() => signOut(true)}>Sign out everywhere</button>
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>

        {/* ------------------------------------------------ explainer, printed like the passbook's conditions page */}
        <aside className="pb-sheet sec-explain" aria-labelledby="sec-explain-title">
          <header className="pb-sheet-head">
            <h2 id="sec-explain-title">Protections on every transfer</h2>
          </header>
          <p className="pb-label">How your account is protected</p>
          <ol className="sec-explain-list">
            <li>
              <span className="sec-explain-ico" aria-hidden="true"><Icon.Fingerprint size={16} /></span>
              <div><b>Passkey approval</b><p>Large payments and first payments to someone new wait until you approve them on your own device.</p></div>
            </li>
            <li>
              <span className="sec-explain-ico" aria-hidden="true"><Icon.Key size={16} /></span>
              <div><b>Transaction PIN</b><p>Every payment needs your 6-digit PIN, so a session left open isn't enough to send money.</p></div>
            </li>
            <li>
              <span className="sec-explain-ico" aria-hidden="true"><Icon.Shield size={16} /></span>
              <div><b>Phishing-resistant</b><p>A passkey only works on this site, and we never see the private half.</p></div>
            </li>
            <li>
              <span className="sec-explain-ico" aria-hidden="true"><Icon.Check size={16} /></span>
              <div><b>Sent exactly once</b><p>Each reviewed transfer carries a one-time key, so a double tap or a retry can't pay twice.</p></div>
            </li>
            <li>
              <span className="sec-explain-ico" aria-hidden="true"><Icon.Clock size={16} /></span>
              <div><b>Sessions expire</b><p>You're signed out after 7 days away, and you can end every session at once.</p></div>
            </li>
          </ol>
        </aside>
      </div>
    </div>
  )
}
