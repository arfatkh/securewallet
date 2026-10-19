import { useEffect, useState } from 'react'
import { api, apiRaw, getAccessToken, newIdempotencyKey } from '../api.js'
import { Banner } from '../components/Bits.jsx'
import * as Icon from '../components/Icons.jsx'
import { rs } from '../format.js'
import { useSession } from '../session.jsx'
import { traceStore } from '../trace.js'
import './Lab.css'

const b64u = s => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const unb64u = s => atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4))
const myBalance = async () => (await apiRaw('/me', { label: 'Check balance' })).data?.wallet?.balance ?? 0
const DEMO_PW = 'Wallet@2026!'
const DEMO_TPIN = '482915' // seeded transaction PIN (W11): the W5-W8 attacks are about other controls, so they carry it

// Each weakness: which lab flags control it, what the attack does, and how to judge the result.
const WEAKNESSES = [
  {
    id: 'W1', flags: ['ownership_check', 'rls'], title: 'Reading another customer\'s wallet (BOLA / IDOR)',
    asset: 'Wallet balance, transaction history', impact: 'Privacy breach; reconnaissance for fraud',
    attack: t => `As you, request /api/wallets/{id} with @${t.username}'s wallet id.`,
    target: 'sara',
    async run(t) {
      const r = await apiRaw(`/wallets/${t.wallet_id}`, { label: 'Attack: read another wallet' })
      return r.status === 200
        ? { hit: true, text: `200 OK: @${r.data.owner.username}'s balance is ${rs(r.data.balance)}`, code: r.status }
        : { hit: false, text: `${r.status}: ${r.data?.detail}`, code: r.status }
    },
  },
  {
    id: 'W2', flags: ['argon2'], title: 'Readable passwords in the database',
    asset: 'User credentials', impact: 'A DB leak or backup copy exposes every password',
    attack: () => 'Register a throwaway account, then dump the users table the way a thief with DB access would.',
    async run() {
      const u = 'probe_' + Math.random().toString(36).slice(2, 7)
      await apiRaw('/auth/register', { method: 'POST', token: null, body: { username: u, full_name: 'Probe Account', password: 'open-sesame-2026' }, label: 'Register probe' })
      const r = await apiRaw('/lab/users-table', { label: 'Dump users table' })
      const row = r.data?.items?.find(x => x.username === u)
      if (!row) return { hit: false, text: 'Could not read the probe row.', code: r.status }
      const plain = row.password_hash.startsWith('plain$')
      return { hit: plain, code: 200, text: plain ? `Stored as text: "${row.password_hash}"` : `Stored as ${row.password_hash.slice(0, 44)}…` }
    },
  },
  {
    id: 'W3', flags: ['login_throttle'], title: 'Password guessing (credential stuffing)',
    asset: 'User credentials, account access', impact: 'Account takeover',
    attack: t => `Try 8 common passwords against @${t.username}, then the real one.`,
    target: 'hina',
    async run(t) {
      const guesses = ['password123', 'pakistan123', 'qwerty123', 'hina1234', 'welcome1', 'iloveyou', 'letmein123', 'Hina@2026']
      const codes = []
      for (const g of [...guesses, DEMO_PW]) {
        const r = await apiRaw('/auth/login', { method: 'POST', token: null, body: { username: t.username, password: g }, label: 'Attack: guess password' })
        codes.push(r.status)
      }
      const last = codes[codes.length - 1]
      return { hit: last === 200, code: last, text: `Responses: ${codes.join(' ')}${last === 200 ? '. Password found: account taken over.' : '. The real password was refused too.'}` }
    },
  },
  {
    id: 'W4', flags: ['jwt_verification'], title: 'Forged session token',
    asset: 'Session token', impact: 'Impersonate any customer',
    attack: t => `Edit your own token's "sub" to @${t.username}'s id, keep the old signature, call /api/me.`,
    target: 'sara',
    async run(t) {
      const [h, p, s] = getAccessToken().split('.')
      const payload = JSON.parse(unb64u(p))
      const forged = `${h}.${b64u(JSON.stringify({ ...payload, sub: t.user_id, name: t.username }))}.${s}`
      const r = await apiRaw('/me', { token: forged, label: 'Attack: forged token' })
      return r.status === 200
        ? { hit: true, code: 200, text: `200 OK: signed in as @${r.data.user.username} with balance ${rs(r.data.wallet.balance)}` }
        : { hit: false, code: r.status, text: `${r.status}: ${r.data?.detail}` }
    },
  },
  {
    id: 'W5', flags: ['amount_validation'], title: 'Negative amount transfer',
    asset: 'Wallet balance', impact: 'Money pulled from someone else\'s wallet',
    attack: t => `Send −Rs 5,000 to @${t.username}.`,
    target: 'sara',
    async run(t) {
      const before = await myBalance()
      const r = await apiRaw('/transfers', { method: 'POST', body: { to_username: t.username, amount: -500000, tpin: DEMO_TPIN }, headers: { 'Idempotency-Key': newIdempotencyKey() }, label: 'Attack: negative amount' })
      const after = await myBalance()
      return after > before
        ? { hit: true, code: r.status, text: `${r.status}: your balance went UP by ${rs(after - before)}` }
        : { hit: false, code: r.status, text: `${r.status}: ${r.data?.detail}` }
    },
  },
  {
    id: 'W6', flags: ['idempotency'], title: 'Replayed / double-submitted transfer',
    asset: 'Wallet balance', impact: 'Customer pays twice',
    attack: t => `Fire the same Rs 1,000 transfer to @${t.username} five times at once (same request, same key).`,
    target: 'sara',
    async run(t) {
      const before = await myBalance()
      const key = newIdempotencyKey()
      const rs5 = await Promise.all(Array.from({ length: 5 }, () => apiRaw('/transfers', { method: 'POST', body: { to_username: t.username, amount: 100000, note: 'Replay test', tpin: DEMO_TPIN }, headers: { 'Idempotency-Key': key }, label: 'Attack: replay' })))
      const paid = Math.round((before - await myBalance()) / 100000)
      return { hit: paid > 1, code: rs5[0].status, text: `5 requests → charged ${paid} time${paid === 1 ? '' : 's'} (${rs(paid * 100000)})` }
    },
  },
  {
    id: 'W7', flags: ['row_locking'], title: 'Race condition on balances',
    asset: 'Wallet balance, ledger integrity', impact: 'Lost updates: money created or destroyed',
    attack: t => `Send ten different Rs 1,000 transfers to @${t.username} in parallel.`,
    target: 'sara',
    async run(t) {
      const before = await myBalance()
      const res = await Promise.all(Array.from({ length: 10 }, (_, i) => apiRaw('/transfers', { method: 'POST', body: { to_username: t.username, amount: 100000, note: `Race ${i + 1}`, tpin: DEMO_TPIN }, headers: { 'Idempotency-Key': newIdempotencyKey() }, label: 'Attack: race' })))
      const ok = res.filter(r => r.status === 201).length
      const debited = before - await myBalance()
      return { hit: debited !== ok * 100000, code: 201, text: `${ok} transfers recorded (${rs(ok * 100000)}) but balance fell by ${rs(debited)}${debited !== ok * 100000 ? ': lost updates. Run reconciliation as the auditor.' : '. Consistent.'}` }
    },
  },
  {
    id: 'W8', flags: ['step_up'], title: 'Large transfer with only a stolen session',
    asset: 'Wallet balance', impact: 'A phished password drains the wallet',
    attack: t => `Send Rs 60,000 to @${t.username} using just the session token (no passkey).`,
    target: 'bilal',
    async run(t) {
      const r = await apiRaw('/transfers', { method: 'POST', body: { to_username: t.username, amount: 6000000, tpin: DEMO_TPIN }, headers: { 'Idempotency-Key': newIdempotencyKey() }, label: 'Attack: no step-up' })
      if (r.status === 201) return { hit: true, code: 201, text: `201: ${rs(6000000)} left the wallet with no passkey` }
      if (r.status === 202) {
        await apiRaw(`/transfers/${r.data.pending_id}/cancel`, { method: 'POST' })
        return { hit: false, code: 202, text: '202: held for passkey approval; nothing moved (cancelled)' }
      }
      return { hit: false, code: r.status, text: `${r.status}: ${r.data?.detail || r.data?.reason}` }
    },
  },
  {
    id: 'W9', flags: ['rbac'], title: 'Customer reaching the audit desk',
    asset: 'Audit log (everyone\'s activity)', impact: 'Data exposure; tampering with evidence',
    attack: () => 'As a customer, call the auditor-only /api/audit and /api/audit/reconcile.',
    async run() {
      const a = await apiRaw('/audit?limit=5', { label: 'Attack: read audit log' })
      const b = await apiRaw('/audit/reconcile', { label: 'Attack: run reconcile' })
      return { hit: a.status === 200, code: a.status, text: `/audit → ${a.status}${a.status === 200 ? ` (${a.data.items.length} entries leaked)` : ''}; /audit/reconcile → ${b.status}${b.status === 403 && a.status === 200 ? ' (the database function still refused)' : ''}` }
    },
  },
  {
    id: 'W12', flags: ['encryption_at_rest'], title: 'Reading the database directly',
    asset: 'Names, transfer notes, audit details', impact: 'A DB dump, stolen backup or curious DBA reads customer data',
    attack: () => 'Register a throwaway account with a full name, then read the users table the way a DBA or backup thief would.',
    async run() {
      const u = 'probe_' + Math.random().toString(36).slice(2, 7)
      await apiRaw('/auth/register', { method: 'POST', token: null, body: { username: u, full_name: 'Probe Person', password: 'open-sesame-2026' }, label: 'Register probe' })
      const r = await apiRaw('/lab/users-table', { label: 'Read users table' })
      const row = r.data?.items?.find(x => x.username === u)
      if (!row) return { hit: false, text: 'Could not read the probe row.', code: r.status }
      const plain = !row.full_name.startsWith('enc:')
      return { hit: plain, code: 200, text: plain ? `full_name stored as text: "${row.full_name}"` : `full_name stored as ${row.full_name.slice(0, 44)}… (AES-256-GCM)` }
    },
  },
  {
    id: 'W11', flags: ['tpin'], title: 'Transfer with a stolen session but no PIN',
    asset: 'Wallet balance', impact: 'A stolen or unattended session sends money',
    attack: t => `With only the session token, send Rs 1,000 to @${t.username} without the transaction PIN.`,
    target: 'sara',
    async run(t) {
      const r = await apiRaw('/transfers', { method: 'POST', body: { to_username: t.username, amount: 100000, note: 'No PIN' }, headers: { 'Idempotency-Key': newIdempotencyKey() }, label: 'Attack: no transaction PIN' })
      return r.status === 201
        ? { hit: true, code: 201, text: `201: ${rs(100000)} sent with no PIN (ref ${r.data.ref})` }
        : { hit: false, code: r.status, text: `${r.status}: ${r.data?.detail || r.data?.reason}` }
    },
  },
  {
    id: 'W13', flags: ['session_timeout'], title: 'Unattended session left signed in',
    asset: 'Account access on a shared or unattended device', impact: 'Anyone at the screen can act as the user',
    attack: () => 'Leave the session completely idle past the limit (no heartbeat), then call /api/me with the same token.',
    async run(_t, ctx) {
      const limit = ctx.config.session?.idle_seconds || 300
      ctx.pauseIdle(true)
      try {
        for (let left = limit + 3; left > 0; left--) {
          ctx.progress(`Idle on purpose… ${left}s`)
          await new Promise(r => setTimeout(r, 1000))
        }
      } finally { ctx.pauseIdle(false) }
      const r = await apiRaw('/me', { label: 'Attack: use an idle session' })
      return r.status === 200
        ? { hit: true, code: 200, text: `200 after ${limit + 3}s idle: the session was still usable.` }
        : { hit: false, code: r.status, text: `${r.status}: ${r.data?.detail}. The server ended the session; sign in again.` }
    },
  },
]

export default function Lab() {
  const { me, signOut, config, pauseIdle, reloadConfig } = useSession()
  const [progress, setProgress] = useState('')
  const [flags, setFlags] = useState(null)
  const [targets, setTargets] = useState([])
  const [runs, setRuns] = useState({})
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState('')
  const [confirmReset, setConfirmReset] = useState(false)

  const load = () => api('/lab/flags').then(d => setFlags(Object.fromEntries(d.items.map(f => [f.name, f])))).catch(e => setError(e.message))
  useEffect(() => { load(); api('/lab/targets').then(d => setTargets(d.items)).catch(() => {}) }, [])

  const toggle = async (name, enabled) => {
    traceStore.beginFlow(`Lab: ${flags[name]?.title} ${enabled ? 'ON' : 'OFF'}`, 'lab')
    setFlags(f => ({ ...f, [name]: { ...f[name], enabled } }))
    try { await api(`/lab/flags/${name}`, { method: 'PUT', body: { enabled }, label: `Lab: ${name} ${enabled ? 'on' : 'off'}` }); reloadConfig() } catch (e) { setError(e.message); load() }
  }

  const run = async w => {
    const t = targets.find(x => x.username === w.target) || targets[0]
    setBusy(w.id); setError('')
    const controlsOn = w.flags.every(f => flags[f]?.enabled)
    traceStore.beginFlow(`${w.id} attack (${controlsOn ? 'after' : 'before'}): ${w.title}`, 'attack')
    try {
      const r = await w.run(t, { config, pauseIdle, progress: setProgress })
      setRuns(x => ({ ...x, [w.id]: [{ ...r, controlsOn, at: new Date() }, ...(x[w.id] || [])].slice(0, 4) }))
    } catch (e) { setError(String(e.message || e)) } finally { setBusy(null); setProgress('') }
  }

  const reset = async () => {
    await api('/lab/reset', { method: 'POST', label: 'Reset demo data' }).catch(() => {})
    signOut()
  }

  if (me.user.role !== 'customer') return <div className="page lab"><Banner kind="warn">Sign in as a customer (e.g. ali) to run the lab attacks.</Banner></div>
  const all = flags ? Object.values(flags) : []
  const offCount = all.filter(f => !f.enabled).length

  return (
    <div className="page lab">
      <header className="lab-head">
        <div className="lab-intro">
          <p className="eyebrow">Presenter · before &amp; after</p>
          <p className="lab-lede">
            Switch a control off and run its attack to show the weakness (before). Switch it back on and run the same attack
            again (after). Every request appears in the security trace, and every switch is written to the audit log.
          </p>
          <div className={`lab-posture-row ${offCount ? 'has-off' : ''}`}>
            <div className="lab-posture" aria-label={`${all.length - offCount} of ${all.length} controls on`}>
              {all.map(f => <i key={f.name} className={f.enabled ? '' : 'off'} title={f.title} />)}
            </div>
            <span className="lab-posture-text">{offCount ? `${offCount} control${offCount > 1 ? 's' : ''} off` : 'All controls on'}</span>
          </div>
        </div>
        <div className="lab-reset">
          {!confirmReset
            ? <button className="btn" onClick={() => setConfirmReset(true)}><Icon.Refresh size={17} />Reset demo data</button>
            : <div className="banner warn lab-confirm">
                <span>Restore every control and the original balances? You'll be signed out.</span>
                <span className="lab-confirm-actions">
                  <button className="btn sm" onClick={() => setConfirmReset(false)}>Keep</button>
                  <button className="btn sm primary" onClick={reset}>Reset</button>
                </span>
              </div>}
        </div>
      </header>
      {error && <div className="lab-error"><Banner>{error}</Banner></div>}
      {!flags ? <p className="muted">Loading…</p> : (
        <div className="lab-grid">
          {WEAKNESSES.map(w => {
            const t = targets.find(x => x.username === w.target) || targets[0] || { username: '…' }
            const off = w.flags.some(f => !flags[f]?.enabled)
            return (
              <article key={w.id} className={`lab-card ${off ? 'off' : ''}`}>
                <div className="lab-card-top">
                  <span className="lab-wid">{w.id}</span>
                  <div className="lab-card-title">
                    <h3>{w.title}</h3>
                    <p className="lab-desc"><span>{w.asset}</span><span aria-hidden="true"> · </span><span>{w.impact}</span></p>
                  </div>
                  {off && <span className="lab-exposed"><Icon.Alert size={14} />Exposed</span>}
                </div>
                <div className="lab-controls">
                  {w.flags.map(name => {
                    const on = !!flags[name]?.enabled
                    return (
                      <label key={name} className={`lab-ctl ${on ? 'is-on' : 'is-off'}`}>
                        <span className="lab-ctl-icon" aria-hidden="true">{on ? <Icon.Shield size={18} /> : <Icon.Alert size={18} />}</span>
                        <span className="lab-ctl-text">
                          <b>{flags[name]?.title}</b>
                          <span className="lab-ctl-desc">{flags[name]?.description}</span>
                        </span>
                        <span className="lab-ctl-state" aria-hidden="true">{on ? 'On' : 'Off'}</span>
                        <button className="switch" role="switch" aria-checked={on} aria-label={flags[name]?.title}
                                onClick={() => toggle(name, !flags[name]?.enabled)} />
                      </label>
                    )
                  })}
                </div>
                <div className="lab-attack"><span className="lab-attack-label">Attack</span> {w.attack(t)}
                  {w.id === 'W1' && t.wallet_id && (
                    <div className="lab-attack-url">Or in the address bar: <a className="mono" href={`/wallet/${t.wallet_id}`}>{`${location.origin}/wallet/${t.wallet_id}`}</a></div>
                  )}
                  {w.id === 'W13' && (
                    <div className="lab-attack-url">
                      Demo idle limit:{' '}
                      <select aria-label="Demo idle limit" value={String(config.session?.idle_seconds || 300)}
                              onChange={async e => {
                                traceStore.beginFlow(`Lab: idle limit ${e.target.value}s`, 'lab')
                                await apiRaw('/lab/settings/session_idle_seconds', { method: 'PUT', body: { value: e.target.value }, label: 'Lab: idle limit' })
                                reloadConfig()
                              }}>
                        {[15, 30, 60, 120, 300].map(s => <option key={s} value={s}>{s < 60 ? `${s} seconds` : `${s / 60} minute${s > 60 ? 's' : ''}`}</option>)}
                      </select>
                    </div>
                  )}
                </div>
                {!!runs[w.id]?.length && (
                  <div className="lab-runs">
                    {runs[w.id].map((r, i) => (
                      <div key={i} className={`lab-run ${r.hit ? 'succeeded' : 'blocked'}`}>
                        <span className="lab-run-tag">{r.controlsOn ? 'After' : 'Before'}</span>
                        <span><b>{r.hit ? 'Attack worked.' : 'Blocked.'}</b> {r.text}</span>
                      </div>
                    ))}
                  </div>
                )}
                <div className="lab-foot">
                  <button className="btn sm primary" onClick={() => run(w)} disabled={!!busy}>
                    <Icon.Play size={14} />{busy === w.id ? (progress || 'Running…') : 'Run attack'}
                  </button>
                  <span className="lab-expect">{off ? 'Control off: expect the attack to work' : 'Control on: expect it to be blocked'}</span>
                </div>
              </article>
            )
          })}
        </div>
      )}
    </div>
  )
}
