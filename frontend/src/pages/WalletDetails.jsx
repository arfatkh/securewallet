import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api.js'
import { Avatar, Banner } from '../components/Bits.jsx'
import * as Icon from '../components/Icons.jsx'
import { amountInWords, rupees } from '../format.js'
import { useSession } from '../session.jsx'
import { traceStore } from '../trace.js'
import './WalletDetails.css'

const acctNo = id => `SW-${id.slice(0, 4)}-${id.slice(4, 8)}-${id.slice(9, 13)}`.toUpperCase()
const hhmm = d => d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })

// Wallet details, addressed by id in the URL (/wallet/<id>). The id is the
// object reference the BOLA check protects: editing it must not reveal
// another customer's wallet.
export default function WalletDetails() {
  const { id } = useParams()
  const { me } = useSession()
  const [state, setState] = useState({ loading: true })

  useEffect(() => {
    setState({ loading: true })
    traceStore.beginFlow(`Open wallet ${id.slice(0, 8)}… from the URL`, 'page')
    api(`/wallets/${encodeURIComponent(id)}`, { label: 'Wallet by id' })
      .then(w => setState({ wallet: w }))
      .catch(e => setState({ error: e }))
  }, [id])

  const mine = state.wallet && state.wallet.owner.username === me.user.username
  const w = state.wallet
  const m = w ? rupees(w.balance) : null
  const asOf = new Date()

  return (
    <div className="page wd">
      <Link to="/" className="btn sm quiet wd-back"><Icon.Back size={16} />Home</Link>
      {state.loading && <p className="muted wd-loading">Loading…</p>}
      {state.error && (
        <section className="pb-sheet wd-missing" aria-labelledby="wd-missing-h">
          <span className="pb-label">Statement unavailable</span>
          <h2 id="wd-missing-h">Wallet not found</h2>
          <p className="muted">There is no wallet with this id on your account.</p>
          <p className="wd-code mono">HTTP {state.error.status} · id {id}</p>
          <div className="pb-stamp bad wd-missing-stamp" aria-hidden="true"><span>Returned</span><b>No record</b></div>
        </section>
      )}
      {w && (
        <>
          {!mine && (
            <Banner>
              This wallet belongs to <b>@{w.owner.username}</b>, not you. The server returned another
              customer's data because the ownership controls are switched off (W1).
            </Banner>
          )}
          <section className={`wd-account ${mine ? '' : 'foreign'}`} aria-label="Wallet statement">
            {/* left page: the printed account form */}
            <div className="wd-form">
              <div className="wd-holder">
                <Avatar name={w.owner.full_name} seed={w.owner.username} size={46} />
                <div className="pb-field wd-wide"><span>Account holder</span><b>{w.owner.full_name}</b></div>
              </div>
              <div className="pb-field"><span>Account no.</span><b className="mono">{acctNo(w.id)}</b></div>
              <div className="pb-field"><span>Username</span><b className="mono">@{w.owner.username}</b></div>
              <div className="pb-field"><span>Currency</span><b className="mono">{w.currency}</b></div>
              <div className="pb-field"><span>Status</span><b className="wd-status">{w.status}</b></div>
              <div className="pb-field wd-wide"><span>Wallet id</span><b className="mono wd-id">{w.id}</b></div>
            </div>

            {/* right page: the balance, ruled, with the as-of stamp */}
            <div className="wd-closing pb-ruled">
              <span className="pb-label">Balance</span>
              <div className="wd-figure num">
                <span className="cur">Rs</span><span className="whole">{m.whole}</span><span className="frac">.{m.frac}</span>
              </div>
              <p className="pb-words wd-words">{amountInWords(w.balance)}</p>
              <div className={`pb-stamp ${mine ? '' : 'bad'}`} role="img" aria-label={mine ? `As of ${asOf.toLocaleString('en-GB')}` : 'Not your account'}>
                {mine ? (<>
                  <span>As of</span>
                  <b>{asOf.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }).toUpperCase()}</b>
                  <span>{hhmm(asOf)} PKT</span>
                </>) : (<>
                  <span>Not your</span><b>Account</b><span>@{w.owner.username}</span>
                </>)}
              </div>
              {mine && (
                <div className="wd-actions">
                  <Link className="btn primary" to="/send"><Icon.Send size={17} />Send money</Link>
                  <Link className="btn" to="/activity"><Icon.Activity size={17} />Full statement</Link>
                </div>
              )}
            </div>
          </section>
        </>
      )}
    </div>
  )
}
