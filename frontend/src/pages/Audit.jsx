import { useCallback, useEffect, useState } from 'react'
import { api } from '../api.js'
import { Banner, Money } from '../components/Bits.jsx'
import * as Icon from '../components/Icons.jsx'
import { dateTime } from '../format.js'
import { traceStore } from '../trace.js'
import './Audit.css'

const OUTCOME_KIND = { success: 'ok', created: 'ok', pending: 'warn', idempotent_replay: 'info', failed: 'bad',
                       denied: 'bad', rejected: 'bad', locked: 'bad', throttled: 'bad', reuse_detected: 'bad', cancelled: 'neutral' }

export default function Audit() {
  const [rows, setRows] = useState(null)
  const [action, setAction] = useState('')
  const [outcome, setOutcome] = useState('')
  const [recon, setRecon] = useState(null)
  const [error, setError] = useState('')

  const load = useCallback(() => {
    const p = new URLSearchParams({ limit: '150' })
    if (action) p.set('action', action)
    if (outcome) p.set('outcome', outcome)
    api('/audit?' + p).then(d => setRows(d.items)).catch(e => { setError(e.message); setRows([]) })
  }, [action, outcome])
  useEffect(() => { load() }, [load])

  const reconcile = async () => {
    setRecon('loading')
    traceStore.beginFlow('Reconcile ledger', 'audit')
    try { setRecon(await api('/audit/reconcile', { label: 'Reconcile ledger' })) } catch (e) { setRecon(null); setError(e.message) }
  }

  const reconState = recon === 'loading' ? 'running' : recon ? (recon.ok ? 'ok' : 'bad') : 'idle'

  const done = recon && recon !== 'loading'

  return (
    <div className="page audit">
      {error && <Banner>{error}</Banner>}

      {/* ------------------------------------------------ reconciliation sheet */}
      <section className={`pb-sheet audit-recon is-${reconState}`} aria-labelledby="audit-recon-h">
        <header className="pb-sheet-head">
          <h2 id="audit-recon-h">Ledger reconciliation</h2>
          <button className="btn primary sm" onClick={reconcile} disabled={recon === 'loading'}><Icon.Refresh size={16} />Run reconciliation</button>
        </header>
        <p className="audit-lede">Checks every wallet against its transaction history, and that no money was created or lost.</p>

        <div className="audit-verify pb-ruled" aria-live="polite">
          <dl className="audit-sum">
            <div><dt>Σ balances <small>all wallets</small></dt><dd className="num">{done ? <Money paisa={recon.total_balances} /> : <span className="audit-blank">—</span>}</dd></div>
            <div><dt>Total supply <small>issued</small></dt><dd className="num">{done ? <Money paisa={recon.total_supply} /> : <span className="audit-blank">—</span>}</dd></div>
            <div className="total"><dt>Difference</dt><dd className="num">{done ? <Money paisa={recon.total_balances - recon.total_supply} /> : <span className="audit-blank">—</span>}</dd></div>
          </dl>
          <div className="audit-verdict">
            <span className="pb-label">Verification status</span>
            {reconState === 'ok' && <span className="pb-stamp ok"><span>Reconciled</span><b>Balanced</b></span>}
            {reconState === 'bad' && <span className="pb-stamp bad"><span>Reconciled</span><b>Mismatch</b></span>}
            {reconState === 'running' && <span className="audit-pending">Verifying…</span>}
            {reconState === 'idle' && <span className="audit-pending">Not run yet</span>}
          </div>
        </div>

        {done && (
          <>
            <Banner kind={recon.ok ? 'ok' : 'error'}>
              {recon.ok ? 'Balanced. Every wallet matches its transactions and total supply is conserved.'
                : 'Mismatch found. Balances do not match the transaction ledger.'}
              {' '}Σ balances <Money paisa={recon.total_balances} /> vs supply <Money paisa={recon.total_supply} />.
            </Banner>
            <div className="audit-scroll audit-scroll-short">
              <table className="pb-table audit-table audit-recon-table">
                <thead><tr><th scope="col">Wallet</th><th scope="col" className="r">Balance</th><th scope="col" className="r">From ledger</th><th scope="col" className="r">Difference</th><th scope="col" className="r"><span className="sr">Status</span></th></tr></thead>
                <tbody>
                  {recon.items.map(i => (
                    <tr key={i.username} className={i.ok ? '' : 'is-bad'}>
                      <td data-label="Wallet" className="audit-who mono">@{i.username}</td>
                      <td data-label="Balance" className="r num audit-money"><Money paisa={i.balance} /></td>
                      <td data-label="From ledger" className="r num audit-money"><Money paisa={i.expected} /></td>
                      <td data-label="Difference" className="r num audit-money"><Money paisa={i.balance - i.expected} /></td>
                      <td data-label="Status" className="r audit-status">{i.ok ? <span className="pb-flag ok">OK</span> : <span className="pb-flag bad">Mismatch</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>

      {/* ------------------------------------------------ audit register */}
      <section className="pb-sheet audit-trail" aria-labelledby="audit-trail-h">
        <header className="pb-sheet-head audit-toolbar">
          <div className="audit-toolbar-title">
            <span className="pb-label">Append-only ledger</span>
            <h2 id="audit-trail-h">Audit trail</h2>
          </div>
          <div className="audit-filters">
            <select className="input audit-select" value={action} onChange={e => setAction(e.target.value)} aria-label="Action">
              <option value="">All actions</option>
              {['auth', 'transfer', 'wallet', 'passkey', 'authz', 'lab'].map(a => <option key={a} value={a}>{a}.*</option>)}
            </select>
            <select className="input audit-select" value={outcome} onChange={e => setOutcome(e.target.value)} aria-label="Outcome">
              <option value="">All outcomes</option>
              {Object.keys(OUTCOME_KIND).map(o => <option key={o} value={o}>{o}</option>)}
            </select>
            <button className="btn sm" onClick={load}><Icon.Refresh size={15} />Refresh</button>
          </div>
        </header>
        <div className="audit-scroll">
          <table className="pb-table audit-table audit-log">
            <thead><tr><th scope="col">#</th><th scope="col">Time</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Outcome</th><th scope="col" className="r">HTTP</th><th scope="col">Detail</th><th scope="col">IP</th></tr></thead>
            <tbody>
              {rows === null && <tr className="audit-empty"><td colSpan={8} className="muted">Loading…</td></tr>}
              {rows?.length === 0 && <tr className="audit-empty"><td colSpan={8} className="muted">No entries match these filters.</td></tr>}
              {rows?.map(r => (
                <tr key={r.id} className={`o-${OUTCOME_KIND[r.outcome] || 'neutral'}`}>
                  <td data-label="#" className="audit-id mono">{r.id}</td>
                  <td data-label="Time" className="audit-time mono">{dateTime(r.ts)}</td>
                  <td data-label="Actor" className="audit-who">{r.actor ? <span className="mono">@{r.actor}</span> : <span className="muted">anonymous</span>}</td>
                  <td data-label="Action"><code className="audit-code">{r.action}</code></td>
                  <td data-label="Outcome" className="audit-outcome"><span className={`pb-flag ${OUTCOME_KIND[r.outcome] || 'neutral'}`}>{r.outcome}</span></td>
                  <td data-label="HTTP" className="r audit-http mono">{r.status_code}</td>
                  <td data-label="Detail" className="audit-detail"><code className="audit-code">{Object.keys(r.detail || {}).length ? JSON.stringify(r.detail) : ''}</code></td>
                  <td data-label="IP" className="audit-ip"><code className="audit-code">{r.ip}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="audit-foot"><Icon.Lock size={15} /><span>Append-only: the database rejects any UPDATE or DELETE on this table. Secrets are redacted before they are written.</span></p>
      </section>
    </div>
  )
}
