import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../api.js'
import { Avatar, Money, StatusPill } from '../components/Bits.jsx'
import * as Icon from '../components/Icons.jsx'
import { amountInWords, dayLabel, rupees, time } from '../format.js'
import { useSession } from '../session.jsx'
import './Activity.css'

// Activity is printed as a bank statement: a header with the account, then month
// sections that open with the balance brought forward, list every entry with the
// balance it left behind, and close with the totals and the balance carried forward.

const signed = t => (t.direction === 'received' ? t.amount : -t.amount)
// Only completed entries on this account move its balance. A leaked row (W1 lab
// demo) is someone else's transfer, so it never touches our running balance.
const counts = t => t.status === 'completed' && !t.leaked
const ddmon = iso => new Date(iso).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }).toUpperCase()
const ddmonyy = d => new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
const hhmm = iso => new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
const fig = p => rupees(p).text.replace(/^−?Rs /, '') // ledger cells: currency is in the column header
const acctNo = id => `SW-${id.slice(0, 4)}-${id.slice(4, 8)}-${id.slice(9, 13)}`.toUpperCase()
const monthOf = iso => { const d = new Date(iso); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}` }
const monthName = iso => new Date(iso).toLocaleDateString('en-GB', { month: 'long', year: 'numeric' })

// Walk back from today's balance (items are newest first): every row gets the
// balance before and after it, so the statement can be read in either direction.
function withRunningBalance(items, current) {
  let bal = current
  return items.map(t => {
    const before = counts(t) ? bal - signed(t) : bal
    const row = { ...t, balanceAfter: bal, balanceBefore: before }
    bal = before
    return row
  })
}

// Month sections, newest month first. Within a month the entries run in date
// order, between the brought-forward and carried-forward lines.
function byMonth(rows) {
  const groups = []
  for (const t of rows) {
    const key = monthOf(t.created_at)
    if (!groups.length || groups[groups.length - 1].key !== key) groups.push({ key, label: monthName(t.created_at), rows: [] })
    groups[groups.length - 1].rows.push(t)
  }
  return groups.map(g => {
    const own = g.rows.filter(counts)
    return {
      ...g,
      rows: [...g.rows].reverse(),
      carried: g.rows[0].balanceAfter,
      brought: g.rows[g.rows.length - 1].balanceBefore,
      debits: own.filter(t => t.direction === 'sent').reduce((s, t) => s + t.amount, 0),
      credits: own.filter(t => t.direction === 'received').reduce((s, t) => s + t.amount, 0),
    }
  })
}

const particulars = t => t.leaked ? `Not your transaction: ${t.between}` : (t.note || (t.direction === 'received' ? 'Received' : 'Sent'))

/* ------------------------------------------------------------------ compact rows
   Kept exported for any caller that wants a short list (Home now uses its own ledger). */

export function TxRow({ t, onOpen }) {
  const incoming = t.direction === 'received'
  const failed = t.status === 'failed'
  return (
    <button className={`act-row ${incoming ? 'in' : 'out'} ${failed ? 'failed' : ''} ${t.leaked ? 'leaked' : ''}`} onClick={() => onOpen?.(t)}>
      <span className="act-row-date"><b>{ddmon(t.created_at)}</b><span>{time(t.created_at)}</span></span>
      <span className="act-row-main">
        <span className="act-row-who">{t.counterparty.full_name}</span>
        <span className="act-row-note">{particulars(t)} · <span className="mono">{t.ref}</span></span>
      </span>
      <span className="act-row-amt">
        <Money paisa={incoming ? t.amount : -t.amount} sign />
        {failed && <span className="pb-flag bad">Not posted</span>}
      </span>
    </button>
  )
}

export function TxList({ data, limit, onOpen }) {
  if (!data) return <div className="act-empty">Loading…</div>
  const items = limit ? data.items.slice(0, limit) : data.items
  if (!items.length && !data.pending?.length) return <div className="act-empty">No transactions yet. Money you send and receive shows up here.</div>
  const groups = []
  for (const t of items) {
    const label = dayLabel(t.created_at)
    if (!groups.length || groups[groups.length - 1][0] !== label) groups.push([label, []])
    groups[groups.length - 1][1].push(t)
  }
  return (
    <div className="act-list">
      {!!data.pending?.length && (
        <div className="act-list-group pending">
          <div className="act-list-day">Waiting for your approval</div>
          {data.pending.map(p => (
            <div key={p.id} className="act-row out pending">
              <span className="act-row-date"><b>{ddmon(p.created_at)}</b><span>exp. {time(p.expires_at)}</span></span>
              <span className="act-row-main"><span className="act-row-who">{p.counterparty.full_name}</span>
                <span className="act-row-note"><StatusPill status="awaiting_passkey" /></span></span>
              <span className="act-row-amt"><Money paisa={-p.amount} sign /></span>
            </div>
          ))}
        </div>
      )}
      {groups.map(([label, rows]) => (
        <div key={label} className="act-list-group">
          <div className="act-list-day">{label}</div>
          {rows.map(t => <TxRow key={t.id} t={t} onOpen={onOpen} />)}
        </div>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------------ voucher */

export function TxSheet({ tx, onClose }) {
  const { me } = useSession()
  const closeRef = useRef(null)
  useEffect(() => {
    const k = e => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [onClose])
  useEffect(() => { // move focus into the voucher, and hand it back when it closes
    const prev = document.activeElement
    closeRef.current?.focus()
    return () => prev?.focus?.()
  }, [])

  const incoming = tx.direction === 'received'
  const you = { full_name: me?.user?.full_name || 'You', username: me?.user?.username || '' }
  let from = incoming ? tx.counterparty : you
  let to = incoming ? you : tx.counterparty
  if (tx.leaked) { // someone else's transfer: show the two parties the server leaked
    const [a, b] = String(tx.between || '').split(' → ')
    from = { full_name: `@${a}`, username: a }
    to = { full_name: `@${b}`, username: b }
  }
  const stamp = tx.status === 'completed' ? ['ok', 'Paid'] : tx.status === 'failed' ? ['bad', 'Not posted'] : ['warn', 'Pending']
  const m = rupees(tx.amount)

  return (
    <div className="act-scrim" onMouseDown={e => e.target === e.currentTarget && onClose()}>
      <div className={`act-voucher ${tx.leaked ? 'leaked' : ''}`} role="dialog" aria-modal="true" aria-labelledby="act-v-title">
        <header className="act-v-head">
          <div>
            <span className="pb-label">SecureWallet · Transaction voucher</span>
            <h2 id="act-v-title">{incoming ? 'Credit voucher' : 'Debit voucher'}</h2>
          </div>
          <button ref={closeRef} className="btn sm quiet" onClick={onClose} aria-label="Close voucher"><Icon.X size={18} /></button>
        </header>

        {tx.leaked && <p className="act-v-leak" role="note">Not your transaction: {tx.between}</p>}

        <div className="act-v-refs">
          <div className="pb-field"><span>Voucher / Ref.</span><b className="mono">{tx.ref}</b></div>
          <div className="pb-field"><span>Date</span><b className="mono">{ddmonyy(tx.created_at).toUpperCase()}</b></div>
          <div className="pb-field"><span>Time</span><b className="mono">{hhmm(tx.created_at)} PKT</b></div>
        </div>

        <div className="act-v-parties">
          <div className="pb-field"><span>From</span><b>{from.full_name}</b>{from.username && <em className="mono">@{from.username}</em>}</div>
          <div className="pb-field"><span>To</span><b>{to.full_name}</b>{to.username && <em className="mono">@{to.username}</em>}</div>
        </div>

        <div className="act-v-amount">
          <span className="pb-label">Amount</span>
          <div className={`act-v-figure ${tx.status === 'failed' ? 'struck' : ''}`}>
            <span className="cur">Rs</span><span className="whole">{m.whole}</span><span className="frac">.{m.frac}</span>
          </div>
          <p className="pb-words"><span className="sr">In words: </span>{amountInWords(tx.amount)}</p>
        </div>

        <div className="act-v-foot">
          <dl className="act-v-dl">
            <div><dt>Note</dt><dd>{tx.note || '—'}</dd></div>
            <div><dt>Fee</dt><dd className="num">Rs 0.00</dd></div>
            {tx.status === 'failed' && tx.reason && <div><dt>Reason</dt><dd>{tx.reason}</dd></div>}
          </dl>
          <div className={`pb-stamp ${stamp[0]}`} role="img" aria-label={`Status: ${stamp[1]}`}>
            <span>SecureWallet</span><b>{stamp[1]}</b><span>{ddmon(tx.created_at)}</span>
          </div>
        </div>

        <p className="act-v-counterfoil pb-perforated">
          <span>Counterfoil</span><span className="mono">{tx.ref}</span><span className="num">{rupees(tx.amount).text}</span>
        </p>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ statement */

function EntryRow({ t, showBal, onOpen }) {
  const failed = t.status === 'failed'
  const open = () => onOpen(t)
  return (
    <tr className={`act-entry ${t.status} ${t.leaked ? 'leaked' : ''}`} tabIndex={0} onClick={open}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open() } }}
        aria-label={`${ddmon(t.created_at)}, ${t.counterparty.full_name}, ${t.direction === 'received' ? 'credit' : 'debit'} ${rupees(t.amount).text}${failed ? ', not posted' : ''}. Open voucher`}>
      <td className="act-date"><b>{ddmon(t.created_at)}</b><span>{hhmm(t.created_at)}</span></td>
      <td className="act-part">
        <span className="act-who">{t.counterparty.full_name}</span>
        <span className="act-note">{particulars(t)}</span>
        <span className="act-ref mono">{t.ref}</span>
      </td>
      {t.leaked ? (
        <td colSpan={2} className="r num act-leak-amt">{fig(t.amount)}</td>
      ) : (<>
        <td className="r num">{t.direction === 'sent' ? fig(t.amount) : ''}</td>
        <td className="r num cr">{t.direction === 'received' ? fig(t.amount) : ''}</td>
      </>)}
      {showBal && (
        <td className="r num act-bal">
          {t.leaked ? <span className="pb-flag bad">Other account</span>
            : counts(t) ? fig(t.balanceAfter)
            : <span className="pb-flag bad" title={t.reason || undefined}>Not posted</span>}
        </td>
      )}
      {!showBal && failed && <td className="r"><span className="pb-flag bad" title={t.reason || undefined}>Not posted</span></td>}
      {!showBal && !failed && <td />}
    </tr>
  )
}

export default function Activity() {
  const { me, reload } = useSession()
  const [dir, setDir] = useState('')
  const [q, setQ] = useState('')
  const [data, setData] = useState(null)
  const [more, setMore] = useState(false)
  const [sheet, setSheet] = useState(null)

  const load = useCallback(async (before) => {
    const params = new URLSearchParams({ limit: '30' })
    if (dir) params.set('direction', dir)
    if (before) params.set('before', before)
    const d = await api('/transactions?' + params)
    setData(prev => before ? { ...d, items: [...prev.items, ...d.items], pending: prev.pending } : d)
  }, [dir])

  useEffect(() => { setData(null); load().catch(() => setData({ items: [], pending: [] })) }, [load])
  // The running balance counts back from today's balance, so make sure it is current.
  useEffect(() => { reload().catch(() => {}) }, [reload])

  const balance = me?.wallet?.balance
  // With a direction filter the server only sends one side, so a running balance
  // would be wrong: it is hidden. Search filters on the client, after the true
  // balance has been worked out on every loaded row.
  const showBal = !dir && balance != null
  const all = useMemo(() => withRunningBalance(data?.items || [], balance ?? 0), [data, balance])
  const months = useMemo(() => byMonth(all), [all])

  const needle = q.trim().toLowerCase()
  const match = t => `${t.counterparty.full_name} ${t.counterparty.username} ${t.note || ''} ${t.ref}`.toLowerCase().includes(needle)
  const shown = needle ? months.map(g => ({ ...g, rows: g.rows.filter(match) })).filter(g => g.rows.length) : months
  const matches = shown.reduce((n, g) => n + g.rows.length, 0)
  const pending = needle ? [] : (data?.pending || [])

  const oldest = all.length ? all[all.length - 1].created_at : null
  const period = oldest ? `${ddmonyy(oldest)} – ${ddmonyy(new Date())}` : '—'
  const cols = 5

  return (
    <div className="page act-page">
      <section className="pb-sheet act-statement" aria-labelledby="act-title">
        {/* ------------------------------------------------ statement header */}
        <header className="act-st-head">
          <div>
            <span className="pb-label">SecureWallet · Statement of account</span>
            <h2 id="act-title">Account statement</h2>
          </div>
          {showBal && (
            <div className="act-st-closing">
              <span className="pb-label">Closing balance</span>
              <b className="num">{rupees(balance).text}</b>
            </div>
          )}
        </header>
        <div className="act-st-fields">
          <div className="pb-field wide"><span>Account holder</span><b className="act-holder">{me?.user?.full_name}</b></div>
          <div className="pb-field"><span>Account no.</span><b className="mono">{me?.wallet ? acctNo(me.wallet.id) : '—'}</b></div>
          <div className="pb-field"><span>Statement period</span><b className="mono">{period}</b></div>
          <div className="pb-field"><span>Currency</span><b>PKR · Rupee</b></div>
        </div>

        {/* ------------------------------------------------ toolbar */}
        <div className="act-toolbar" role="toolbar" aria-label="Statement filters">
          <div className="act-seg" role="group" aria-label="Filter">
            {[['', 'All'], ['sent', 'Sent'], ['received', 'Received']].map(([v, l]) => (
              <button key={l} aria-pressed={dir === v} onClick={() => setDir(v)}>{l}</button>
            ))}
          </div>
          <label className="act-search">
            <Icon.Search size={16} className="act-search-ico" />
            <input className="input" type="search" placeholder="Search name, note or reference"
                   value={q} onChange={e => setQ(e.target.value)} aria-label="Search transactions" />
          </label>
        </div>
        {(dir || needle) && data && (
          <p className="act-notice" role="status">
            {dir && <>Balance column hidden: only {dir} entries are listed, so a running balance would not add up. Choose <b>All</b> to see it. </>}
            {needle && <>{matches} of {all.length} loaded entr{all.length === 1 ? 'y' : 'ies'} match “{q.trim()}”.{showBal && ' Balances shown are the account’s true balances.'}</>}
          </p>
        )}

        {/* ------------------------------------------------ ledger */}
        <div className="act-table-wrap">
          <table className="pb-table margin act-table">
            <caption className="sr">Statement entries by month, with debit, credit{showBal ? ' and running balance' : ''}</caption>
            <thead>
              <tr>
                <th scope="col">Date</th><th scope="col">Particulars</th>
                <th scope="col" className="r">Debit <small>Rs</small></th>
                <th scope="col" className="r">Credit <small>Rs</small></th>
                <th scope="col" className="r">{showBal ? <>Balance <small>Rs</small></> : <span className="sr">Status</span>}</th>
              </tr>
            </thead>

            {!!pending.length && (
              <tbody className="act-pending">
                <tr className="act-month"><th colSpan={cols} scope="rowgroup">Awaiting your approval</th></tr>
                {pending.map(p => (
                  <tr key={p.id} className="pending">
                    <td className="act-date"><b>{ddmon(p.created_at)}</b><span>{hhmm(p.created_at)}</span></td>
                    <td className="act-part"><span className="act-who">{p.counterparty.full_name}</span>
                      <span className="act-note">Awaiting passkey approval · expires {time(p.expires_at)}</span></td>
                    <td className="r num">{fig(p.amount)}</td><td />
                    <td className="r"><span className="pb-flag warn">Not posted</span></td>
                  </tr>
                ))}
              </tbody>
            )}

            {shown.map(g => (
              <tbody key={g.key}>
                <tr className="act-month"><th colSpan={cols} scope="rowgroup">{g.label}</th></tr>
                {showBal && (
                  <tr className="act-bf">
                    <td className="act-date" /><td>Brought forward</td><td /><td />
                    <td className="r num act-bal">{fig(g.brought)}</td>
                  </tr>
                )}
                {g.rows.map(t => <EntryRow key={t.id} t={t} showBal={showBal} onOpen={setSheet} />)}
                {showBal ? (
                  <tr className="act-cf">
                    <td className="act-date" /><td>Carried forward <small>month totals</small></td>
                    <td className="r num">{fig(g.debits)}</td><td className="r num cr">{fig(g.credits)}</td>
                    <td className="r num act-bal">{fig(g.carried)}</td>
                  </tr>
                ) : (
                  <tr className="act-cf">
                    <td className="act-date" /><td>Month total <small>posted</small></td>
                    <td className="r num">{dir === 'sent' ? fig(g.debits) : ''}</td>
                    <td className="r num cr">{dir === 'received' ? fig(g.credits) : ''}</td><td />
                  </tr>
                )}
              </tbody>
            ))}

            {data && !shown.length && !pending.length && (
              <tbody><tr><td colSpan={cols} className="act-empty">
                {needle ? 'No loaded entries match your search.' : 'No transactions yet. Money you send and receive is posted here.'}
              </td></tr></tbody>
            )}
            {!data && <tbody><tr><td colSpan={cols} className="act-empty">Loading…</td></tr></tbody>}
          </table>
        </div>

        {data?.next_before && !needle && (
          <div className="act-more">
            <button className="btn sm" disabled={more} onClick={async () => { setMore(true); await load(data.next_before).catch(() => {}); setMore(false) }}>
              {more ? 'Loading…' : 'Load older'}
            </button>
          </div>
        )}
        {data && !data.next_before && !dir && !needle && all.length > 0 && (
          <p className="act-end">End of statement · first entry {ddmonyy(oldest)}</p>
        )}
      </section>
      {sheet && <TxSheet tx={sheet} onClose={() => setSheet(null)} />}
    </div>
  )
}
