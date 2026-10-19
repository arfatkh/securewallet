import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api.js'
import AddBeneficiary from '../components/AddBeneficiary.jsx'
import { Avatar, Money } from '../components/Bits.jsx'
import * as Icon from '../components/Icons.jsx'
import { amountInWords, rupees, rs } from '../format.js'
import { useSession } from '../session.jsx'
import { TxSheet } from './Activity.jsx'
import './Home.css'

// Home is laid out as a bank passbook: the account page (holder, number, closing
// balance), the balance trail, the ledger with a running balance on every line,
// the month's reconciliation, the account's security endorsements, and payee slips.

const signed = t => (t.direction === 'received' ? t.amount : -t.amount)
const posted = t => t.status === 'completed'
const ddmon = iso => new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }).toUpperCase()
const hhmm = iso => new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
const fig = p => rupees(p).text.replace(/^−?Rs /, '') // ledger cells: currency is in the column header
const acctNo = id => `SW-${id.slice(0, 4)}-${id.slice(4, 8)}-${id.slice(9, 13)}`.toUpperCase()

// Walk back from today's balance: every posted line gets the balance it left behind.
function withRunningBalance(items, current) {
  let bal = current
  return items.map(t => {
    const row = { ...t, balanceAfter: bal }
    if (posted(t)) bal -= signed(t)
    return row
  })
}

function useWidth() {
  const ref = useRef(null)
  const [w, setW] = useState(640)
  useLayoutEffect(() => {
    if (!ref.current) return
    const ro = new ResizeObserver(([e]) => setW(Math.max(280, Math.round(e.contentRect.width))))
    ro.observe(ref.current)
    return () => ro.disconnect()
  }, [])
  return [ref, w]
}

// Step chart: a balance only changes when something is posted, so it is drawn in steps, not slopes.
function BalanceTrail({ rows, current, hidden }) {
  const [wrapRef, width] = useWidth()
  const [hover, setHover] = useState(null)
  const H = 168, pad = { l: 8, r: 92, t: 18, b: 26 }

  const pts = useMemo(() => rows.filter(posted).slice(0, 14).reverse() // the last 14 postings, oldest first
    .map(t => ({ at: new Date(t.created_at).getTime(), bal: t.balanceAfter, t })), [rows])

  if (pts.length < 2) return <p className="pb-trail-empty">Your balance trail appears after your first payment.</p>

  const now = Date.now()
  const x0 = pts[0].at, x1 = now
  const lo = Math.min(...pts.map(p => p.bal)), hi = Math.max(...pts.map(p => p.bal))
  const span = hi - lo || Math.max(1, hi * 0.1)
  const X = t => pad.l + (t - x0) / (x1 - x0) * (width - pad.l - pad.r)
  const Y = v => pad.t + (1 - (v - (lo - span * 0.12)) / (span * 1.24)) * (H - pad.t - pad.b)
  let d = `M${X(pts[0].at)},${Y(pts[0].bal)}`
  for (const p of pts.slice(1)) d += `H${X(p.at)}V${Y(p.bal)}`
  d += `H${X(now)}`
  const ticks = [lo, lo + span / 2, hi]
  const k = v => (v / 100000).toLocaleString('en-PK', { maximumFractionDigits: 1 })
  const last = pts[pts.length - 1]

  const onMove = e => {
    const r = e.currentTarget.getBoundingClientRect()
    const mx = (e.clientX - r.left) * (width / r.width)
    let best = pts[0]
    for (const p of pts) if (Math.abs(X(p.at) - mx) < Math.abs(X(best.at) - mx)) best = p
    setHover(best)
  }

  return (
    <div className="pb-trail" ref={wrapRef}>
      <svg width={width} height={H} viewBox={`0 0 ${width} ${H}`} role="img"
           aria-label={`Balance trail: ${hidden ? 'hidden' : `from ${rs(pts[0].bal)} to ${rs(current)}`}`}
           onPointerMove={onMove} onPointerLeave={() => setHover(null)}>
        {ticks.map((v, i) => (
          <g key={i}>
            <line x1={pad.l} x2={width - pad.r} y1={Y(v)} y2={Y(v)} className="pb-gline" />
            <text x={width - pad.r + 10} y={Y(v) + 4} className="pb-tick">{hidden ? '••••' : `${k(v)}k`}</text>
          </g>
        ))}
        <path d={`${d}V${H - pad.b}H${X(pts[0].at)}Z`} className="pb-area" />
        <path d={d} className="pb-line" />
        {hover && (
          <g>
            <line x1={X(hover.at)} x2={X(hover.at)} y1={pad.t - 6} y2={H - pad.b} className="pb-cross" />
            <circle cx={X(hover.at)} cy={Y(hover.bal)} r="5" className="pb-dot" />
          </g>
        )}
        <circle cx={X(now)} cy={Y(last.bal)} r="5" className="pb-dot end" />
        <text x={pad.l} y={H - 6} className="pb-tick">{ddmon(new Date(x0).toISOString())}</text>
        <text x={width - pad.r} y={H - 6} textAnchor="end" className="pb-tick">TODAY</text>
      </svg>
      {hover?.t && (
        <div className="pb-tip" style={{ left: Math.min(Math.max(X(hover.at), 90), width - 180) }}>
          <div className="pb-tip-date">{ddmon(hover.t.created_at)} · {hhmm(hover.t.created_at)}</div>
          <div className="pb-tip-who">{hover.t.counterparty.full_name}</div>
          <div className={`pb-tip-amt ${hover.t.direction === 'received' ? 'cr' : ''}`}><Money paisa={signed(hover.t)} sign /></div>
          <div className="pb-tip-bal">Balance {hidden ? '••••' : rs(hover.bal)}</div>
        </div>
      )}
    </div>
  )
}

// One strip per month: a cell per day, a mark above for money in, below for money out.
function PostingCalendar({ rows, monthStart, hidden }) {
  const days = new Date(monthStart.getFullYear(), monthStart.getMonth() + 1, 0).getDate()
  const today = new Date()
  const byDay = {}
  for (const t of rows) {
    const d = new Date(t.created_at)
    if (!posted(t) || d < monthStart || d.getMonth() !== monthStart.getMonth()) continue
    const k = d.getDate()
    byDay[k] = byDay[k] || { in: 0, out: 0, n: 0 }
    byDay[k][t.direction === 'received' ? 'in' : 'out'] += t.amount
    byDay[k].n++
  }
  const label = (day, v) => {
    const date = new Date(monthStart.getFullYear(), monthStart.getMonth(), day).toLocaleDateString('en-GB', { day: 'numeric', month: 'long' })
    if (!v) return `${date}: no postings`
    return `${date}: ${v.n} posting${v.n > 1 ? 's' : ''}` + (hidden ? '' : `${v.in ? `, in ${rs(v.in)}` : ''}${v.out ? `, out ${rs(v.out)}` : ''}`)
  }
  return (
    <div className="pb-cal" role="list" aria-label="Posting calendar">
      {Array.from({ length: days }, (_, i) => i + 1).map(day => {
        const v = byDay[day]
        const isToday = day === today.getDate() && monthStart.getMonth() === today.getMonth()
        const future = monthStart.getMonth() === today.getMonth() && day > today.getDate()
        return (
          <span key={day} role="listitem" title={label(day, v)} aria-label={label(day, v)}
                className={`pb-cal-day${isToday ? ' today' : ''}${future ? ' future' : ''}`}>
            <i className={v?.in ? 'in' : ''} />
            <b>{day}</b>
            <i className={v?.out ? 'out' : ''} />
          </span>
        )
      })}
    </div>
  )
}

function Seal({ ok, title, detail, icon: Ico }) {
  return (
    <li className={`pb-seal ${ok ? 'ok' : 'todo'}`}>
      <span className="pb-seal-mark" aria-hidden="true"><Ico size={20} /></span>
      <span className="pb-seal-text">
        <b>{title}</b>
        <span>{detail}</span>
      </span>
      <span className="pb-seal-state">{ok ? 'Active' : 'Not set'}</span>
    </li>
  )
}

export default function Home() {
  const { me, reload, config } = useSession()
  const nav = useNavigate()
  const [tx, setTx] = useState(null)
  const [contacts, setContacts] = useState([])
  const [benefs, setBenefs] = useState(null)
  const [adding, setAdding] = useState(false)
  const [sheet, setSheet] = useState(null)
  const [hidden, setHidden] = useState(() => { try { return localStorage.getItem('sw.hide') === '1' } catch { return false } })

  useEffect(() => {
    reload().catch(() => {})
    api('/transactions?limit=100').then(setTx).catch(() => setTx({ items: [], pending: [] }))
    api('/contacts').then(d => setContacts(d.items)).catch(() => {})
    api('/beneficiaries').then(d => setBenefs(d.items)).catch(() => setBenefs([]))
  }, [reload])

  const removeBenef = async b => {
    try { await api(`/beneficiaries/${b.id}`, { method: 'DELETE', label: 'Remove beneficiary' }); setBenefs(xs => xs.filter(x => x.id !== b.id)) } catch { /* already gone */ }
  }

  const toggleHidden = () => setHidden(h => { try { localStorage.setItem('sw.hide', h ? '0' : '1') } catch { /* private mode */ } return !h })
  const balance = me.wallet.balance
  const rows = useMemo(() => withRunningBalance(tx?.items || [], balance), [tx, balance])

  // Month reconciliation: brought forward + deposits − withdrawals = carried forward.
  const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0)
  const inMonth = rows.filter(t => posted(t) && new Date(t.created_at) >= monthStart)
  const deposits = inMonth.filter(t => t.direction === 'received').reduce((s, t) => s + t.amount, 0)
  const withdrawals = inMonth.filter(t => t.direction === 'sent').reduce((s, t) => s + t.amount, 0)
  const broughtForward = balance - deposits + withdrawals
  const monthName = monthStart.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' })

  const m = rupees(balance)
  const asOf = new Date()
  const idleMin = Math.max(1, Math.round((config.session?.idle_seconds || 300) / 60))
  const mask = v => (hidden ? '••••••' : v)

  return (
    <div className="page pb">
      {/* ------------------------------------------------ account page */}
      <section className="pb-account" aria-label="Account">
        <div className="pb-form">
          <div className="pb-field wide"><span>Account holder</span><b>{me.user.full_name}</b></div>
          <div className="pb-field"><span>Account no.</span>
            <button className="pb-acct mono" onClick={() => nav(`/wallet/${me.wallet.id}`)} title="Wallet details">{acctNo(me.wallet.id)}</button>
          </div>
          <div className="pb-field"><span>Username</span><b className="mono">@{me.user.username}</b></div>
          <div className="pb-field"><span>Member since</span><b>{new Date(me.user.member_since).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}</b></div>
          <div className="pb-field"><span>Currency</span><b>PKR · Rupee</b></div>
        </div>

        <div className="pb-closing">
          <div className="pb-closing-head">
            <span className="pb-label">Closing balance</span>
            <button className="pb-eye" onClick={toggleHidden} aria-label={hidden ? 'Show balance' : 'Hide balance'}>
              {hidden ? <Icon.Eye size={16} /> : <Icon.EyeOff size={16} />}{hidden ? 'Show' : 'Hide'}
            </button>
          </div>
          <div className="pb-figure num" aria-live="polite">
            <span className="cur">Rs</span>
            {hidden ? <span className="masked">• • • • • •</span> : <><span className="whole">{m.whole}</span><span className="frac">.{m.frac}</span></>}
          </div>
          {!hidden && <p className="pb-words">{amountInWords(balance)}</p>}
          <div className="pb-stamp" aria-label={`As of ${asOf.toLocaleString('en-GB')}`}>
            <span>As of</span>
            <b>{asOf.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }).toUpperCase()}</b>
            <span>{hhmm(asOf.toISOString())} PKT</span>
          </div>
          <div className="pb-actions">
            <button className="btn primary" onClick={() => nav('/send')}><Icon.Send size={17} />Send money</button>
            <button className="btn" onClick={() => nav('/activity')}><Icon.Activity size={17} />Full statement</button>
          </div>
        </div>
      </section>

      <div className="pb-grid">
        <div className="pb-main">
          {/* ------------------------------------------------ balance trail */}
          <section className="pb-sheet" aria-labelledby="pb-trail-h">
            <header className="pb-sheet-head">
              <h2 id="pb-trail-h">Balance trail</h2>
              <span className="pb-hint">Each step is one posting. Hover to read it.</span>
            </header>
            {tx ? <BalanceTrail rows={rows} current={balance} hidden={hidden} /> : <p className="pb-trail-empty">Loading…</p>}
          </section>

          {/* ------------------------------------------------ ledger */}
          <section className="pb-sheet pb-ledger" aria-labelledby="pb-ledger-h">
            <header className="pb-sheet-head">
              <h2 id="pb-ledger-h">Ledger</h2>
              <Link to="/activity">Full statement →</Link>
            </header>
            <div className="pb-table-wrap">
              <table className="pb-table">
                <thead>
                  <tr><th>Date</th><th>Particulars</th><th className="r">Debit <small>Rs</small></th><th className="r">Credit <small>Rs</small></th><th className="r">Balance <small>Rs</small></th></tr>
                </thead>
                <tbody>
                  {(tx?.pending || []).map(p => (
                    <tr key={p.id} className="pending">
                      <td className="pb-date"><b>{ddmon(p.created_at)}</b><span>{hhmm(p.created_at)}</span></td>
                      <td><span className="pb-who">{p.counterparty.full_name}</span><span className="pb-note">Awaiting passkey approval</span></td>
                      <td className="r num">{fig(p.amount)}</td><td />
                      <td className="r"><span className="pb-flag warn">Not posted</span></td>
                    </tr>
                  ))}
                  {rows.slice(0, 9).map(t => (
                    <tr key={t.id} className={t.status} onClick={() => setSheet(t)} tabIndex={0}
                        onKeyDown={e => e.key === 'Enter' && setSheet(t)}>
                      <td className="pb-date"><b>{ddmon(t.created_at)}</b><span>{hhmm(t.created_at)}</span></td>
                      <td>
                        <span className="pb-who">{t.counterparty.full_name}</span>
                        <span className="pb-note">{t.note || (t.direction === 'received' ? 'Received' : 'Sent')} · <span className="mono">{t.ref}</span></span>
                      </td>
                      <td className="r num">{t.direction === 'sent' ? fig(t.amount) : ''}</td>
                      <td className="r num cr">{t.direction === 'received' ? fig(t.amount) : ''}</td>
                      <td className="r num pb-run">
                        {posted(t) ? mask(fig(t.balanceAfter)) : <span className="pb-flag bad" title={t.reason}>Not posted</span>}
                      </td>
                    </tr>
                  ))}
                  {tx && !rows.length && !(tx.pending || []).length && (
                    <tr><td colSpan={5} className="pb-empty">No entries yet. Money you send and receive is posted here.</td></tr>
                  )}
                  {!tx && <tr><td colSpan={5} className="pb-empty">Loading…</td></tr>}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        <aside className="pb-side">
          {/* ------------------------------------------------ month reconciliation */}
          <section className="pb-sheet pb-recon" aria-labelledby="pb-recon-h">
            <header className="pb-sheet-head"><h2 id="pb-recon-h">{monthName}</h2></header>
            <dl>
              <div><dt>Brought forward</dt><dd className="num">{mask(rs(broughtForward))}</dd></div>
              <div><dt>Deposits <small>({inMonth.filter(t => t.direction === 'received').length})</small></dt><dd className="num cr">+ {rs(deposits)}</dd></div>
              <div><dt>Withdrawals <small>({inMonth.filter(t => t.direction === 'sent').length})</small></dt><dd className="num">− {rs(withdrawals)}</dd></div>
              <div className="total"><dt>Carried forward</dt><dd className="num">{mask(rs(balance))}</dd></div>
            </dl>
            <div className="pb-cal-head">
              <span className="pb-label">Posting days</span>
              <span className="pb-cal-key"><i className="in" />in <i className="out" />out</span>
            </div>
            <PostingCalendar rows={rows} monthStart={monthStart} hidden={hidden} />
          </section>

          {/* ------------------------------------------------ security endorsements */}
          <section className="pb-sheet pb-endorse" aria-labelledby="pb-endorse-h">
            <header className="pb-sheet-head"><h2 id="pb-endorse-h">Endorsements</h2></header>
            <p className="pb-hint">What protects this account right now.</p>
            <ul>
              <Seal ok title="Password" detail="Stored only as an argon2id hash" icon={Icon.Lock} />
              <Seal ok={me.has_tpin} title="Transaction PIN" detail={me.has_tpin ? 'Required on every payment' : 'Needed before you can send'} icon={Icon.Key} />
              <Seal ok={me.passkeys > 0} title="Passkey" detail={me.passkeys > 0 ? `${me.passkeys} device${me.passkeys > 1 ? 's' : ''} for large payments` : 'Needed for payments over Rs 50,000'} icon={Icon.Fingerprint} />
              <Seal ok title="Session guard" detail={`Signs out after ${idleMin} min without activity`} icon={Icon.Clock} />
            </ul>
            {(!me.has_tpin || me.passkeys === 0) && (
              <button className="btn sm" onClick={() => nav('/security')}>Complete in Security →</button>
            )}
          </section>

          {/* ------------------------------------------------ payee slips */}
          <section className="pb-sheet pb-payees" aria-labelledby="pb-payees-h">
            <header className="pb-sheet-head"><h2 id="pb-payees-h">Beneficiaries</h2><span className="pb-hint">Saved with your PIN</span></header>
            <div className="pb-slips">
              {(benefs || []).map(b => (
                <div key={b.id} className="pb-slip-row">
                  <button className="pb-slip" onClick={() => nav(`/send?to=${encodeURIComponent(b.username)}`)}>
                    <Avatar name={b.full_name} seed={b.username} size={34} />
                    <span><b>{b.nickname || b.full_name}</b><span className="mono">{b.nickname ? `${b.full_name} · ` : ''}@{b.username}</span></span>
                    <span className="pb-slip-go">Pay →</span>
                  </button>
                  <button className="pb-slip-remove" onClick={() => removeBenef(b)} aria-label={`Remove ${b.full_name} from beneficiaries`} title="Remove">
                    <Icon.X size={14} />
                  </button>
                </div>
              ))}
              {benefs && !benefs.length && <p className="pb-hint">No saved payees yet.</p>}
              <button className="pb-slip new" onClick={() => setAdding(true)}>
                <span className="pb-slip-plus"><Icon.Plus size={18} /></span>
                <span><b>Add beneficiary</b><span>Needs your transaction PIN</span></span>
              </button>
            </div>
          </section>
        </aside>
      </div>
      {sheet && <TxSheet tx={sheet} onClose={() => setSheet(null)} />}
      {adding && <AddBeneficiary onClose={() => setAdding(false)}
                                 onAdded={b => { setBenefs(xs => [b, ...(xs || [])]); setAdding(false) }} />}
    </div>
  )
}
