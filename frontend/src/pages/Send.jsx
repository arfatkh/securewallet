import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { api, newIdempotencyKey } from '../api.js'
import AddBeneficiary from '../components/AddBeneficiary.jsx'
import { Avatar, Banner, Money } from '../components/Bits.jsx'
import * as Icon from '../components/Icons.jsx'
import { amountInWords, dateTime, parseRupees, rs } from '../format.js'
import { useSession } from '../session.jsx'
import { traceStore } from '../trace.js'
import { approveWithPasskey, passkeysSupported } from '../webauthn.js'
import './Send.css'

// Send money is written as a cheque: Pay, Rupees (in words), the boxed figures, a memo,
// the drawer's signature (the transaction PIN) and the MICR band. The receipt is the
// counterfoil torn off along the perforation, stamped PAID or NOT PAID.

const acctNo = id => `SW-${id.slice(0, 4)}-${id.slice(4, 8)}-${id.slice(9, 13)}`.toUpperCase()
const stampDate = d => d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }).toUpperCase()

function PasskeyPrompt({ pending, onDone, onCancel }) {
  const [state, setState] = useState('ready') // ready | waiting | error
  const [error, setError] = useState('')
  const approve = async () => {
    setState('waiting'); setError('')
    try {
      const credential = await approveWithPasskey(pending.options)
      const result = await api(`/transfers/${pending.pending_id}/confirm`, { method: 'POST', body: { credential }, label: 'Confirm with passkey' })
      onDone(result)
    } catch (e) {
      if (e.data?.status === 'failed') return onDone(e.data)
      setError(e.message); setState('error')
    }
  }
  const cancel = async () => {
    try { await api(`/transfers/${pending.pending_id}/cancel`, { method: 'POST' }) } catch { /* expired already */ }
    onCancel()
  }
  return (
    <div className="send-scrim">
      <div className="send-pk" role="dialog" aria-modal="true" aria-labelledby="pk-title" aria-describedby="pk-lede">
        <header className="send-pk-head">
          <span className="pb-flag warn">Held for approval</span>
          <span className="send-pk-ref mono">Not yet paid</span>
        </header>
        <div className="send-pk-body">
          <div className="send-pk-title-row">
            <span className="send-pk-seal" aria-hidden="true"><Icon.Fingerprint size={26} /></span>
            <h2 id="pk-title" className="send-pk-title">Approve with your passkey</h2>
          </div>
          <p id="pk-lede" className="send-pk-lede">
            You're sending <b>{rs(pending.amount)}</b> to <b>{pending.counterparty.full_name}</b>.
            {' '}Your device will ask for your fingerprint, face or PIN.
          </p>
          <div className="send-pk-cheque">
            <div className="send-pk-line"><span className="pb-label">Pay</span><b>{pending.counterparty.full_name}</b></div>
            <div className="send-pk-line"><span className="pb-label">Rupees</span><span className="pb-words">{amountInWords(pending.amount)}</span></div>
            <div className="send-pk-line fig"><span className="pb-label">Rs</span><b className="num">{rs(pending.amount).replace(/^Rs /, '')}</b></div>
          </div>
          <div className="send-pk-why">
            <span className="pb-label">Extra check because</span>
            <p>{pending.risk.signals.join('; ')}.</p>
          </div>
          {error && <Banner>{error}</Banner>}
          <div className="send-pk-actions">
            <button className="btn primary block" onClick={approve} disabled={state === 'waiting'}>
              {state === 'waiting' ? 'Waiting for your device…' : state === 'error' ? 'Try again' : 'Approve transfer'}
            </button>
            <button className="btn quiet block" onClick={cancel} disabled={state === 'waiting'}>Cancel transfer</button>
          </div>
        </div>
      </div>
    </div>
  )
}

const STEPS = ['Recipient', 'Amount', 'Review', 'Receipt']

function Stepper({ step }) {
  return (
    <ol className="send-steps" aria-label="Transfer progress">
      {STEPS.map((label, i) => (
        <li key={label} className={i < step ? 'done' : i === step ? 'on' : ''} aria-current={i === step ? 'step' : undefined}>
          <span className="send-step-n">{i < step ? <Icon.Check size={13} /> : String(i + 1).padStart(2, '0')}</span>
          <span className="send-step-l">{label}</span>
        </li>
      ))}
    </ol>
  )
}

// The printed date boxes in the cheque's top-right corner: D D M M Y Y Y Y.
function DateBoxes({ date }) {
  const dd = String(date.getDate()).padStart(2, '0')
  const mm = String(date.getMonth() + 1).padStart(2, '0')
  const yyyy = String(date.getFullYear())
  const group = (s, k) => <span className="send-chq-date-g" key={k}>{[...s].map((c, i) => <span key={i}>{c}</span>)}</span>
  return (
    <div className="send-chq-date" aria-label={`Date ${date.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' })}`}>
      <span className="pb-label" aria-hidden="true">Date</span>
      <span className="send-chq-date-boxes mono" aria-hidden="true">{group(dd, 'd')}{group(mm, 'm')}{group(yyyy, 'y')}</span>
    </div>
  )
}

// The cheque leaf. Each line is a slot so the same leaf is filled in across the steps.
function Cheque({ me, state, pay, words, figures, memo, sign, fee }) {
  return (
    <article className={`send-chq ${state}`} aria-label="Cheque">
      <header className="send-chq-top">
        <div className="send-chq-bank">
          <span className="send-chq-bank-name">SecureWallet</span>
          <span className="send-chq-bank-sub mono">Wallet cheque · PKR</span>
        </div>
        <span className="send-chq-cross" aria-hidden="true">A/C payee only</span>
        <DateBoxes date={new Date()} />
      </header>

      <div className="send-chq-line send-chq-pay">
        <span className="send-chq-k" aria-hidden="true">Pay</span>
        <div className="send-chq-v">{pay}</div>
      </div>

      <div className="send-chq-mid">
        <div className="send-chq-line send-chq-words">
          <span className="send-chq-k" aria-hidden="true">Rupees</span>
          <div className="send-chq-v">{words}</div>
        </div>
        <div className="send-chq-fig">
          {figures}
          {fee}
        </div>
      </div>

      <div className="send-chq-foot">
        <div className="send-chq-line send-chq-memo">
          <span className="send-chq-k" aria-hidden="true">Memo</span>
          <div className="send-chq-v">{memo}</div>
        </div>
        <div className="send-chq-sign">
          {sign}
          <span className="send-chq-sign-for">for {me.user.full_name}</span>
        </div>
      </div>

      <footer className="send-chq-micr mono" aria-label="Drawer">
        <span><span className="send-chq-micr-k">Drawer</span>{me.user.full_name}</span>
        <span><span className="send-chq-micr-k">A/C</span>{acctNo(me.wallet.id)}</span>
        <span>@{me.user.username}</span>
      </footer>
    </article>
  )
}

export default function Send() {
  const { me, config, reload } = useSession()
  const nav = useNavigate()
  const [params] = useSearchParams()
  const [step, setStep] = useState(0) // 0 recipient, 1 amount, 2 review, 3 done
  const [handle, setHandle] = useState(params.get('to') || '')
  const [person, setPerson] = useState(null)
  const [contacts, setContacts] = useState([])
  const [benefs, setBenefs] = useState([])
  const [adding, setAdding] = useState(false)
  const [lookupErr, setLookupErr] = useState('')
  const [amountText, setAmountText] = useState('')
  const [note, setNote] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState(null)
  const [result, setResult] = useState(null)
  // W11: the transaction PIN. Kept only in this component's state and cleared after every attempt.
  const [tpin, setTpin] = useState('')
  const [pinErr, setPinErr] = useState(null) // { code, text }
  // One key per reviewed transfer: a double-click or a network retry reuses it,
  // so the server pays once.
  const idemKey = useRef(null)
  const flowId = useRef(null)
  const limits = config.limits || {}

  useEffect(() => {
    api('/contacts').then(d => setContacts(d.items)).catch(() => {})
    api('/beneficiaries').then(d => setBenefs(d.items)).catch(() => {})
  }, [])
  const saved = new Set(benefs.map(b => b.username))
  useEffect(() => { if (params.get('to')) find(params.get('to')) }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function find(u = handle) {
    setLookupErr('')
    const clean = u.trim().replace(/^@/, '').toLowerCase()
    if (!clean) return
    // One flow per transfer: lookup, send, passkey ceremony, confirm and the balance refresh.
    flowId.current = traceStore.beginFlow(`Send money → @${clean}`, 'transfer')
    try {
      const p = await api(`/users/lookup?username=${encodeURIComponent(clean)}`, { label: 'Find recipient' })
      if (p.is_self) { setLookupErr("That's you. Pick someone else."); return }
      setPerson(p); setStep(1)
    } catch (e) { setLookupErr(e.message) }
  }

  const amount = parseRupees(amountText)
  const amountErr = amountText && amount === null ? 'Enter an amount like 2,000 or 2,000.50'
    : amount !== null && amount < 1 ? 'Enter an amount above zero'
    : amount > (limits.max_transfer || Infinity) ? `The most you can send at once is ${rs(limits.max_transfer)}`
    : amount > me.wallet.balance ? `That's more than your balance of ${rs(me.wallet.balance)}` : ''
  const needsPasskey = useMemo(() => amount && person && (amount > limits.stepup_amount || (!person.paid_before && amount > limits.new_payee_amount)), [amount, person, limits])

  const confirm = async () => {
    if (!/^\d{6}$/.test(tpin)) { setPinErr({ code: 'tpin_missing', text: 'Enter your 6-digit transaction PIN.' }); return }
    setBusy(true); setError(''); setPinErr(null)
    traceStore.tagFlow({ label: `Transfer ${rs(amount)} → @${person.username}` }, flowId.current)
    try {
      const r = await api('/transfers', {
        method: 'POST', body: { to_username: person.username, amount, note: note.trim() || undefined, tpin },
        headers: { 'Idempotency-Key': idemKey.current }, label: 'Send money',
      })
      setTpin('')
      if (r.status === 'awaiting_passkey') setPending(r)
      else finish(r)
    } catch (e) {
      setTpin('')
      if (e.data?.status === 'failed') finish(e.data)
      else if (e.data?.code?.startsWith('tpin_')) setPinErr({ code: e.data.code, text: e.message })
      else setError(e.message)
    } finally { setBusy(false) }
  }
  const pinLocked = pinErr?.code === 'tpin_locked'
  const noPin = !me.has_tpin || pinErr?.code === 'tpin_required'
  const toSecurity = e => { e.preventDefault(); nav('/security') }
  const finish = r => {
    traceStore.tagFlow({ ref: r.ref, outcome: r.status }, flowId.current)
    setPending(null); setResult(r); setStep(3); reload().catch(() => {})
  }

  // Shared cheque slots
  const blank = <span className="send-chq-blank" aria-hidden="true" />
  const payee = person && (
    <div className="send-chq-payee">
      <Avatar name={person.full_name} seed={person.username} size={34} />
      <span className="send-chq-payee-text">
        <b>{person.full_name}</b>
        <span className="mono">@{person.username}</span>
      </span>
      {!person.paid_before && <span className="pb-flag info">First payment</span>}
    </div>
  )
  const words = (paisa, placeholder, faded) => paisa
    ? <span className={`pb-words send-chq-words-text ${faded ? 'faded' : ''}`}>{amountInWords(paisa)}</span>
    : <span className="send-chq-placeholder">{placeholder}</span>
  const figures = paisa => (
    <div className="send-chq-box filled" aria-label={`Amount in figures ${rs(paisa)}`}>
      <span className="send-chq-box-cur" aria-hidden="true">Rs</span>
      <span className="send-chq-box-num num" aria-hidden="true">{rs(paisa).replace(/^Rs /, '')}<span className="send-chq-box-end">/-</span></span>
    </div>
  )

  return (
    <div className="page send">
      <Stepper step={step} />

      {step === 0 && (
        <section className="send-stage" aria-labelledby="send-h0">
          <header className="send-head">
            <h2 id="send-h0" className="send-h">Who are you paying?</h2>
            <p className="pb-hint">Write the payee's SecureWallet username on the Pay line.</p>
          </header>
          <Cheque me={me} state="blank"
            pay={
              <form className="send-find" onSubmit={e => { e.preventDefault(); find() }}>
                <span className="send-at" aria-hidden="true">@</span>
                <input className="send-chq-input send-handle" placeholder="username" value={handle}
                       onChange={e => setHandle(e.target.value)} autoCapitalize="none" spellCheck="false" aria-label="Recipient username" autoFocus />
                <button className="btn primary sm" disabled={!handle.trim()}>Continue</button>
              </form>
            }
            words={<span className="send-chq-placeholder">The amount is written here in words</span>}
            figures={<div className="send-chq-box" aria-hidden="true"><span className="send-chq-box-cur">Rs</span></div>}
            memo={blank}
            sign={<span className="send-chq-sign-line" aria-hidden="true" />}
          />
          {lookupErr && <Banner>{lookupErr}</Banner>}
          <section className="pb-sheet send-recent" aria-labelledby="send-benef-h">
            <header className="pb-sheet-head">
              <h2 id="send-benef-h">Saved beneficiaries</h2>
              <button className="btn sm" onClick={() => setAdding(true)}><Icon.Plus size={15} />Add beneficiary</button>
            </header>
            {benefs.length ? (
              <div className="send-recent-list">
                {benefs.map(b => (
                  <button key={b.id} className="send-person" onClick={() => { setHandle(b.username); find(b.username) }}>
                    <Avatar name={b.full_name} seed={b.username} size={34} />
                    <span className="send-person-text"><b>{b.nickname || b.full_name}</b><span className="mono">{b.nickname ? `${b.full_name} · ` : ''}@{b.username}</span></span>
                    <span className="send-person-go">Pay →</span>
                  </button>
                ))}
              </div>
            ) : <p className="pb-hint">No saved payees yet. Adding one needs your transaction PIN.</p>}
          </section>
          {!!contacts.filter(c => !saved.has(c.username)).length && (
            <section className="pb-sheet send-recent" aria-labelledby="send-recent-h">
              <header className="pb-sheet-head">
                <h2 id="send-recent-h">Recent payees</h2>
                <span className="pb-hint">Pick one to fill the Pay line</span>
              </header>
              <div className="send-recent-list">
                {contacts.filter(c => !saved.has(c.username)).map(c => (
                  <button key={c.username} className="send-person" onClick={() => { setHandle(c.username); find(c.username) }}>
                    <Avatar name={c.full_name} seed={c.username} size={34} />
                    <span className="send-person-text"><b>{c.full_name}</b><span className="mono">@{c.username}</span></span>
                    <span className="send-person-go">Pay →</span>
                  </button>
                ))}
              </div>
            </section>
          )}
        </section>
      )}

      {step === 1 && person && (
        <section className="send-stage" aria-labelledby="send-h1">
          <header className="send-head">
            <div>
              <h2 id="send-h1" className="send-h">How much?</h2>
              <p className="pb-hint">Write the amount in figures. The words fill in as you type.</p>
            </div>
            <button className="btn sm quiet send-back" onClick={() => setStep(0)}><Icon.Back size={16} />Change recipient</button>
          </header>
          <form className="send-amount-form" onSubmit={e => { e.preventDefault(); if (amount && !amountErr) { idemKey.current = newIdempotencyKey(); setPinErr(x => (x?.code === 'tpin_locked' ? x : null)); setStep(2) } }}>
            <Cheque me={me} state="writing"
              pay={payee}
              words={words(amount, 'The amount is written here in words', !!amountErr)}
              figures={
                <label className={`send-chq-box editable ${amountErr ? 'invalid' : ''}`} htmlFor="amount">
                  <span className="send-chq-box-cur">Rs</span>
                  <input id="amount" inputMode="decimal" placeholder="0" value={amountText} autoFocus autoComplete="off"
                         aria-label="Amount in rupees" aria-describedby="send-balance"
                         onChange={e => setAmountText(e.target.value.replace(/[^\d.,]/g, ''))} aria-invalid={!!amountErr} />
                </label>
              }
              memo={
                <input id="note" className="send-chq-input" maxLength={140} value={note} onChange={e => setNote(e.target.value)}
                       placeholder="What's it for? (optional)" aria-label="Memo (optional)" />
              }
              sign={<span className="send-chq-sign-line" aria-hidden="true" />}
            />
            <div className="send-under">
              <p className="send-balance" id="send-balance">Balance <Money paisa={me.wallet.balance} /></p>
              <div className="send-quick" aria-label="Quick amounts">
                {[500, 1000, 2000, 5000].map(v => <button type="button" key={v} className="btn sm" onClick={() => setAmountText(v.toLocaleString('en-PK'))}>Rs {v.toLocaleString('en-PK')}</button>)}
              </div>
            </div>
            {amountErr && <p className="error send-amount-err" role="alert">{amountErr}</p>}
            {needsPasskey && !amountErr && (
              <Banner kind="warn">
                You'll approve this with your passkey.{' '}
                {me.passkeys === 0 && <>You don't have one yet: <a href="/security" onClick={e => { e.preventDefault(); nav('/security') }}>add a passkey</a> first.</>}
              </Banner>
            )}
            <button className="btn primary block send-go" disabled={!amount || !!amountErr}>Review</button>
          </form>
        </section>
      )}

      {step === 2 && (
        <section className="send-stage" aria-labelledby="send-h2">
          <header className="send-head">
            <div>
              <h2 id="send-h2" className="send-h">Check the details</h2>
              <p className="pb-hint">Nothing is sent until you sign with your PIN and confirm.</p>
            </div>
            <button className="btn sm quiet send-back" onClick={() => { setTpin(''); setStep(1) }}><Icon.Back size={16} />Edit</button>
          </header>
          <Cheque me={me} state="complete"
            pay={payee}
            words={words(amount)}
            figures={figures(amount)}
            fee={<p className="send-chq-fee"><span>Fee <span className="num">Rs 0.00</span></span><span>They receive <Money paisa={amount} /></span></p>}
            memo={note.trim() ? <span className="send-chq-memo-text">{note.trim()}</span> : <span className="send-chq-placeholder">No memo</span>}
            sign={noPin ? (
              <div className="send-nopin">
                <span className="pb-flag warn">Unsigned</span>
                <span>No transaction PIN set</span>
              </div>
            ) : (
              <form className="send-pin" onSubmit={e => { e.preventDefault(); confirm() }} autoComplete="off">
                <label htmlFor="tpin" className="send-pin-label"><Icon.Lock size={14} />Authorise with your transaction PIN</label>
                <input id="tpin" className={`send-pin-input ${pinErr && !pinLocked ? 'invalid' : ''}`} type="password"
                       inputMode="numeric" autoComplete="off" maxLength={6} pattern="\d{6}" placeholder="••••••"
                       value={tpin} disabled={busy || pinLocked} aria-invalid={!!pinErr && !pinLocked}
                       aria-describedby="tpin-help" onChange={e => { setTpin(e.target.value.replace(/\D/g, '').slice(0, 6)); setPinErr(null) }} />
              </form>
            )}
          />
          {!noPin && <p id="tpin-help" className="pb-hint send-pin-help">The 6-digit PIN you set in Security is your signature. We never show or store it in your browser.</p>}
          {noPin && (
            <Banner kind="warn">
              You need a transaction PIN to send money.{' '}
              <a href="/security" onClick={toSecurity}>Set one in Security</a>, then come back.
            </Banner>
          )}
          {needsPasskey && <Banner kind="warn">Your passkey will be needed to approve this transfer.</Banner>}
          {pinErr && !noPin && <Banner kind={pinLocked ? 'warn' : 'error'}>{pinErr.text}</Banner>}
          {error && <Banner>{error}</Banner>}
          <button className="btn primary block send-go" onClick={confirm} disabled={busy || noPin || pinLocked || tpin.length !== 6}>{busy ? 'Sending…' : `Send ${rs(amount)}`}</button>
          {!passkeysSupported() && needsPasskey && <p className="hint">This browser doesn't support passkeys.</p>}
        </section>
      )}

      {step === 3 && result && (
        <section className={`send-stage send-receipt ${result.status === 'completed' ? 'ok' : 'fail'}`} aria-labelledby="send-h3">
          <div className="send-stub">
            <div className="send-send-stub-paper">
              <header className="send-send-stub-head">
                <div>
                  <span className="pb-label">SecureWallet · Counterfoil</span>
                  <h2 id="send-h3" className="send-send-stub-title">
                    {result.status === 'completed' ? `Paid to ${result.counterparty.full_name}` : "Transfer didn't go through"}
                  </h2>
                </div>
                {result.status === 'completed' ? (
                  <div className="pb-stamp ok send-send-stub-stamp" role="img" aria-label="Paid">
                    <span>SecureWallet</span><b>Paid</b><span>{stampDate(new Date())}</span>
                  </div>
                ) : (
                  <div className="pb-stamp bad send-send-stub-stamp" role="img" aria-label="Not paid">
                    <span>Returned</span><b>Not paid</b><span>{stampDate(new Date())}</span>
                  </div>
                )}
              </header>

              <div className="send-send-stub-amount">
                <div className={`send-send-stub-fig num ${result.status === 'completed' ? '' : 'void'}`}>
                  <span className="cur">Rs</span>{rs(result.amount).replace(/^Rs /, '')}
                </div>
                <p className="pb-words">{amountInWords(result.amount)}</p>
              </div>

              {result.status !== 'completed' && <Banner>Reason: {result.reason}. No money left your wallet.</Banner>}

              <dl className="send-send-stub-dl">
                <div className="pb-field"><dt>Reference</dt><dd className="mono">{result.ref}</dd></div>
                <div className="pb-field"><dt>Date</dt><dd className="mono">{dateTime(new Date().toISOString())}</dd></div>
                <div className="pb-field wide"><dt>Pay</dt><dd>{result.counterparty.full_name} <span className="mono muted">@{result.counterparty.username}</span></dd></div>
                {note.trim() && <div className="pb-field wide"><dt>Memo</dt><dd>{note.trim()}</dd></div>}
                {result.status === 'completed' && <div className="pb-field wide send-send-stub-bal"><dt>Your new balance</dt><dd><Money paisa={result.balance_after} /></dd></div>}
              </dl>
              <p className="send-send-stub-micr mono">{acctNo(me.wallet.id)} · {me.user.full_name}</p>
            </div>
          </div>
          <div className="send-receipt-actions">
            <button className="btn block" onClick={() => { setStep(0); setPerson(null); setAmountText(''); setNote(''); setResult(null) }}>Send another</button>
            <button className="btn primary block" onClick={() => nav('/')}>Done</button>
          </div>
        </section>
      )}

      {adding && <AddBeneficiary onClose={() => setAdding(false)}
                                 onAdded={b => { setBenefs(xs => [b, ...xs]); setAdding(false) }} />}
      {pending && <PasskeyPrompt pending={pending} onDone={finish} onCancel={() => { setPending(null); idemKey.current = newIdempotencyKey(); setError('Transfer cancelled. No money was sent.') }} />}
    </div>
  )
}
