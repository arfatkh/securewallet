import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import { Banner } from '../components/Bits.jsx'
import Guilloche from '../components/Guilloche.jsx'
import { Logo } from '../components/Icons.jsx'
import { useSession } from '../session.jsx'
import { traceStore } from '../trace.js'
import './Auth.css'

const DEMO = ['ali', 'sara', 'bilal', 'hina', 'auditor']

// The brand side is the passbook's cloth-bound cover: a stitched spine, a blind-tooled
// frame, and the seal embossed in the centre.
function Art() {
  return (
    <section className="auth-cover" aria-label="About SecureWallet">
      <span className="auth-spine" aria-hidden="true" />
      <div className="auth-cover-face">
        <Link to="/" className="auth-emboss">
          <span className="auth-seal" aria-hidden="true">
            <Guilloche className="auth-seal-rosette" />
            <Logo size={64} />
          </span>
          <span className="auth-name">SecureWallet</span>
          <span className="auth-kicker">Passbook · Pakistani rupee</span>
        </Link>
        <div className="auth-pitch">
          <h1>Your money, kept under <em>lock and ledger.</em></h1>
          <p>Passwords are hashed with argon2id and never stored as typed. Large transfers are signed with a passkey on your own device, so a stolen password alone moves nothing.</p>
        </div>
        <dl className="auth-facts">
          <div><dt>argon2id</dt><dd>password hashing</dd></div>
          <div><dt>Passkeys</dt><dd>for large transfers</dd></div>
          <div><dt>Rs 0</dt><dd>fee between wallets</dd></div>
        </dl>
      </div>
    </section>
  )
}

function PasswordField({ id, value, onChange, autoComplete, invalid }) {
  const [show, setShow] = useState(false)
  return (
    <div className="input-wrap">
      <input id={id} className="input" type={show ? 'text' : 'password'} value={value} autoComplete={autoComplete}
             onChange={e => onChange(e.target.value)} aria-invalid={invalid || undefined} required />
      <button type="button" className="btn sm quiet peek" onClick={() => setShow(s => !s)}>{show ? 'Hide' : 'Show'}</button>
    </div>
  )
}

export function Login() {
  const { signIn, config, signedOutReason } = useSession()
  const nav = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async e => {
    e.preventDefault()
    setBusy(true); setError('')
    traceStore.beginFlow(`Sign in as @${username.trim().toLowerCase()}`, 'auth')
    try {
      const s = await api('/auth/login', { method: 'POST', body: { username, password }, token: null, label: 'Sign in' })
      await signIn(s)
      nav(s.user.role === 'auditor' ? '/audit' : '/', { replace: true })
    } catch (err) {
      setError(err.status === 0 ? 'Can\'t reach SecureWallet. Check your connection.' : err.message)
    } finally { setBusy(false) }
  }

  return (
    <div className="auth">
      <Art />
      <div className="auth-form-wrap">
        <form className="auth-form" onSubmit={submit} noValidate>
          <div className="auth-head">
            <p className="auth-step">Sign in</p>
            <h2>Welcome back</h2>
            <p className="muted">Sign in to your wallet.</p>
          </div>
          {!error && signedOutReason && <Banner kind="warn">{signedOutReason}</Banner>}
          {error && <Banner>{error}</Banner>}
          <div className="field auth-line">
            <label htmlFor="username">Username</label>
            <input id="username" className="input" value={username} onChange={e => setUsername(e.target.value)}
                   autoComplete="username" autoCapitalize="none" spellCheck="false" required />
          </div>
          <div className="field auth-line">
            <label htmlFor="password">Password</label>
            <PasswordField id="password" value={password} onChange={setPassword} autoComplete="current-password" />
          </div>
          <button className="btn primary block" disabled={busy || !username || !password}>{busy ? 'Signing in…' : 'Sign in'}</button>
          <p className="auth-switch">New to SecureWallet? <Link to="/register">Open a wallet</Link></p>
          {config.demo_available && (
            <details className="auth-demo">
              <summary>Demo accounts</summary>
              <p className="hint auth-demo-pw">Password for all: <code className="mono">Wallet@2026!</code></p>
              <div className="auth-accts">
                {DEMO.map(u => (
                  <button type="button" key={u} onClick={() => { setUsername(u); setPassword('Wallet@2026!') }}>{u}</button>
                ))}
              </div>
            </details>
          )}
        </form>
      </div>
    </div>
  )
}

export function Register() {
  const { signIn } = useSession()
  const nav = useNavigate()
  const [f, setF] = useState({ full_name: '', username: '', password: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const set = k => v => setF(x => ({ ...x, [k]: v }))
  const u = f.username.trim().toLowerCase()
  const rules = [
    [f.password.length >= 10, 'At least 10 characters'],
    [!!f.password && !(u && f.password.toLowerCase().includes(u)), 'Doesn\'t contain your username'],
  ]
  const userOk = /^[a-z0-9_]{3,24}$/.test(u)

  const submit = async e => {
    e.preventDefault()
    setBusy(true); setError('')
    traceStore.beginFlow(`Create account @${u}`, 'auth')
    try {
      const s = await api('/auth/register', { method: 'POST', body: { ...f, username: u }, token: null, label: 'Create account' })
      await signIn(s)
      nav('/', { replace: true })
    } catch (err) { setError(err.message) } finally { setBusy(false) }
  }

  return (
    <div className="auth">
      <Art />
      <div className="auth-form-wrap">
        <form className="auth-form" onSubmit={submit} noValidate>
          <div className="auth-head">
            <p className="auth-step">New account · Account-opening form</p>
            <h2>Open your wallet</h2>
            <p className="muted">It takes less than a minute.</p>
          </div>
          {error && <Banner>{error}</Banner>}
          <div className="field auth-line">
            <label htmlFor="full_name">Full name</label>
            <input id="full_name" className="input" value={f.full_name} onChange={e => set('full_name')(e.target.value)} autoComplete="name" required />
          </div>
          <div className="field auth-line">
            <label htmlFor="new-username">Username</label>
            <input id="new-username" className="input" value={f.username} onChange={e => set('username')(e.target.value)}
                   autoComplete="username" autoCapitalize="none" spellCheck="false" aria-invalid={!!f.username && !userOk} />
            <span className={`hint${f.username && !userOk ? ' auth-hint-bad' : ''}`}>People send you money using this. 3–24 letters, numbers or _.</span>
          </div>
          <div className="field auth-line">
            <label htmlFor="new-password">Password</label>
            <PasswordField id="new-password" value={f.password} onChange={set('password')} autoComplete="new-password" />
            <div className="auth-rules">
              {rules.map(([ok, t]) => <span key={t} className={ok ? 'ok' : ''}><span className="auth-rule-mark" aria-hidden="true">{ok ? '✓' : ''}</span> {t}<span className="sr">{ok ? ' (met)' : ' (not met)'}</span></span>)}
            </div>
          </div>
          <button className="btn primary block" disabled={busy || !userOk || f.full_name.trim().length < 2 || !rules.every(r => r[0])}>
            {busy ? 'Creating…' : 'Create wallet'}
          </button>
          <p className="auth-switch">Already have a wallet? <Link to="/login">Sign in</Link></p>
        </form>
      </div>
    </div>
  )
}
