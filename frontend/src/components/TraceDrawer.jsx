import { useEffect, useState } from 'react'
import { explain } from '../explain.js'
import { traceStore, useTrace } from '../trace.js'
import * as Icon from './Icons.jsx'
import './TraceDrawer.css'

function Step({ s, open, onToggle }) {
  return (
    <div className={`tr-st ${s.status} ${open ? '' : 'collapsed'}`}>
      <span className="tr-dot" aria-hidden="true" />
      <div className="tr-st-title" onClick={onToggle} role="button" tabIndex={0} aria-expanded={open}
           onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && onToggle()}>
        <span className={`tr-lane ${s.lane}`}>{s.lane}</span>
        <span className="tr-st-name">{s.title}</span>
        <span className="tr-layer">{s.layer}</span>
        {s.t_ms != null && <span className="tr-toff">+{s.t_ms} ms</span>}
      </div>
      <div className="tr-st-body">
        {s.jwt && (
          <>
            <div className="tr-legend"><span><i className="tr-sw h" />header</span><span><i className="tr-sw p" />payload</span><span><i className="tr-sw s" />signature</span></div>
            <div className="tr-jwt"><span className="h">{s.jwt.header}</span>.<span className="p">{s.jwt.payload}</span>.<span className="s">{s.jwt.signature}</span></div>
          </>
        )}
        {s.bytes && (
          <>
            <div className="tr-legend">{s.bytes.map(g => <span key={g.label}><i className={`tr-sw b-${g.tone}`} />{g.label}</span>)}</div>
            <div className="tr-bytes">
              {s.bytes.flatMap(g => g.hex.match(/../g).map((b, i) => <span key={g.label + i} className={g.tone}>{b}</span>))}
              {s.bytes.some(g => g.tone === 'd') && <span className="d">…</span>}
            </div>
          </>
        )}
        {s.data && <dl className="tr-kv">{s.data.map(([k, v], i) => <div key={i} style={{ display: 'contents' }}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>}
        {s.checks && <div className="tr-checks">{s.checks.map(([ok, t], i) => <div key={i}><span className={ok ? 'y' : 'n'}>{ok ? '✓' : '✗'}</span><span>{t}</span></div>)}</div>}
        {s.math && <pre className="tr-math">{s.math.join('\n')}</pre>}
        {s.explain && <p className="tr-explain">{s.explain}</p>}
      </div>
    </div>
  )
}

const clock = d => d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + '.' + String(d.getMilliseconds()).padStart(3, '0')

function Explanation({ e }) {
  const x = explain(e)
  return (
    <div className="tr-why">
      <div className="tr-why-title">{x.title}</div>
      <p>{x.what}</p>
      <p className="tr-why-outcome"><b>{e.status || 'Browser'}</b> · {x.outcome}</p>
      {!!x.controls.length && <div className="tr-why-controls">{x.controls.map(c => <span key={c} className="tr-tag">{c}</span>)}</div>}
      {x.say && <p className="tr-why-say"><b>Say it in the demo:</b> {x.say}</p>}
    </div>
  )
}

const LANE_ORDER = ['Browser', 'Authenticator', 'API', 'Database', 'Gateway']
// Which parts of the system a request actually touched, from where its steps ran.
const lanesOf = e => LANE_ORDER.filter(l => e.steps.some(s => s.lane === l))
  .concat([...new Set(e.steps.map(s => s.lane))].filter(l => !LANE_ORDER.includes(l)))

const KIND_LABEL = { transfer: 'Transfer', attack: 'Attack', auth: 'Sign-in', passkey: 'Passkey', lab: 'Lab switch', audit: 'Audit', page: 'Page', payee: 'Payee' }

function FlowChip({ flow, onFilter, active }) {
  if (!flow) return null
  return (
    <button className={`tr-chip ${flow.kind} ${active ? 'on' : ''}`} onClick={() => onFilter(active ? null : flow.id)}
            title={active ? 'Show all requests' : 'Show only requests from this action'}>
      <span className="tr-chip-kind">{KIND_LABEL[flow.kind] || 'Action'}</span>
      <span className="tr-chip-label">{flow.label}{flow.ref ? ` · ${flow.ref}` : ''}</span>
    </button>
  )
}

function Request({ e, expanded, onToggle, limit, flow, onFilter, filtered }) {
  const [openSteps, setOpenSteps] = useState({})
  const [why, setWhy] = useState(false)
  const steps = limit == null ? e.steps : e.steps.slice(0, limit)
  const codeClass = `s${String(e.status)[0]}`
  const fails = e.steps.filter(s => s.status === 'fail').length
  return (
    <div className={`tr-req ${fails ? 'has-fail' : ''} ${expanded ? 'is-open' : ''}`}>
      <div className="tr-req-top">
        <button className="tr-req-head" onClick={onToggle} aria-expanded={expanded}>
          <span className={`tr-method ${e.method}`}>{e.method === 'BROWSER' ? 'WEB' : e.method}</span>
          <span className="tr-req-path">
            {e.method === 'BROWSER' ? e.path : `/api${e.path}`}
            {e.label && e.method !== 'BROWSER' && <span className="tr-req-label"> · {e.label}</span>}
          </span>
          <span className={`tr-code ${codeClass}`}>{e.status || `${e.steps.length} steps`}{fails ? ` · ${fails}✗` : ''}</span>
        </button>
        <div className="tr-req-tags">
          {lanesOf(e).map(l => <span key={l} className={`tr-lane ${l}`}>{l}</span>)}
          <FlowChip flow={flow} onFilter={onFilter} active={filtered} />
        </div>
        <div className="tr-req-meta">
          <span className="tr-req-time" title={e.at.toISOString()}><Icon.Clock size={12} />{clock(e.at)}{e.ms != null ? ` · ${e.ms} ms round trip` : ''} · {e.steps.length} steps</span>
          <button className={`tr-why-btn ${why ? 'on' : ''}`} onClick={() => setWhy(w => !w)} aria-expanded={why}>
            <Icon.Info size={13} />{why ? 'Hide' : 'Explain'}
          </button>
        </div>
      </div>
      {why && <Explanation e={e} />}
      {expanded && (
        <div className="tr-steps">
          {steps.map(s => (
            <Step key={s.seq} s={s} open={openSteps[s.seq] ?? true}
                  onToggle={() => setOpenSteps(o => ({ ...o, [s.seq]: !(o[s.seq] ?? true) }))} />
          ))}
        </div>
      )}
    </div>
  )
}

function toMarkdown(entries) {
  return entries.slice().reverse().map(e => [
    `### ${e.method} ${e.method === 'BROWSER' ? e.path : '/api' + e.path} → ${e.status || 'browser'}  (${clock(e.at)}${e.ms != null ? `, ${e.ms} ms` : ''})`,
    `> ${explain(e).what}`,
    ...e.steps.map(s => [
      `${s.seq}. **[${s.lane} · ${s.layer}] ${s.title}**: ${String(s.status).toUpperCase()}`,
      ...(s.data || []).map(([k, v]) => `   - ${k}: \`${v}\``),
      ...(s.checks || []).map(([ok, t]) => `   - ${ok ? '✓' : '✗'} ${t}`),
      ...(s.math ? ['   ```', ...s.math.map(m => '   ' + m), '   ```'] : []),
    ].join('\n')),
  ].join('\n')).join('\n\n')
}

function FlowSummary({ flow, entries }) {
  const first = entries[entries.length - 1], last = entries[0]
  const span = last && first ? last.at - first.at + (last.ms || 0) : 0
  const lanes = LANE_ORDER.filter(l => entries.some(e => e.steps.some(s => s.lane === l)))
  const fails = entries.reduce((n, e) => n + e.steps.filter(s => s.status === 'fail').length, 0)
  return (
    <div className="tr-summary">
      <div className="tr-summary-kind">{KIND_LABEL[flow.kind] || 'Action'} · started {clock(flow.at)}</div>
      <div className="tr-summary-title">{flow.label}</div>
      {flow.ref && <div className="tr-summary-ref">Reference {flow.ref}{flow.outcome ? ` · ${flow.outcome}` : ''}</div>}
      <div className="tr-summary-stats">
        <span><b>{entries.length}</b> request{entries.length === 1 ? '' : 's'}</span>
        <span><b>{entries.reduce((n, e) => n + e.steps.length, 0)}</b> checks</span>
        <span><b>{fails}</b> failed</span>
        <span><b>{span}</b> ms total</span>
      </div>
      <div className="tr-req-tags tr-flush">{lanes.map(l => <span key={l} className={`tr-lane ${l}`}>{l}</span>)}</div>
      <ol className="tr-summary-steps">
        {entries.slice().reverse().map(e => (
          <li key={e.id}><span className="tr-mono">{e.method === 'BROWSER' ? 'WEB' : e.method} {e.method === 'BROWSER' ? e.path : e.path.split('?')[0]}</span> <span className={`tr-code s${String(e.status)[0]}`}>{e.status || ''}</span></li>
        ))}
      </ol>
    </div>
  )
}

export default function TraceDrawer({ open }) {
  const { entries: all, flows, filter, stepMode } = useTrace()
  const flowById = Object.fromEntries(flows.map(f => [f.id, f]))
  const counts = all.reduce((m, e) => ({ ...m, [e.flow]: (m[e.flow] || 0) + 1 }), {})
  const entries = filter == null ? all
    : typeof filter === 'string' ? all.filter(e => flowById[e.flow]?.kind === filter)
    : all.filter(e => e.flow === filter)
  const activeFlow = typeof filter === 'number' ? flowById[filter] : null
  const [expanded, setExpanded] = useState({})
  const [shown, setShown] = useState(0)
  const [copied, setCopied] = useState(false)
  // Focus the newest *action* (a write or a labelled call), not a background GET refresh.
  const latest = entries.find(e => e.method !== 'GET' || e.label) || entries[0]

  // Step-through: reveal the newest request one step at a time (→ key or button).
  useEffect(() => { setShown(stepMode ? 1 : 0) }, [latest?.id, stepMode])
  useEffect(() => {
    if (!stepMode) return
    const onKey = e => { if (e.key === 'ArrowRight' && !/INPUT|TEXTAREA/.test(document.activeElement?.tagName)) setShown(n => n + 1) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [stepMode])

  const copy = async () => {
    try { await navigator.clipboard.writeText(toMarkdown(entries)); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* clipboard blocked */ }
  }

  return (
    <aside className={`trace tr ${open ? 'open' : ''}`} aria-label="Security trace">
      <div className="tr-head">
        <div className="tr-row">
          <h2 className="tr-title"><span className="tr-live" aria-hidden="true" /><span>Security trace</span><span className="tr-title-sub">inspector</span></h2>
          <button className="btn sm quiet" onClick={() => traceStore.clear()} disabled={!entries.length}>Clear</button>
        </div>
        <div className="tr-row">
          <select className="input tr-select" value={filter ?? ''} aria-label="Filter by action"
                  onChange={ev => { const v = ev.target.value; traceStore.setFilter(v === '' ? null : /^\d+$/.test(v) ? Number(v) : v) }}>
            <option value="">All actions ({all.length} requests)</option>
            <option value="transfer">All transfers</option>
            <option value="attack">All lab attacks</option>
            <optgroup label="Single action">
              {flows.filter(f => counts[f.id]).map(f => (
                <option key={f.id} value={f.id}>{clock(f.at).slice(0, 8)} · {f.label}{f.ref ? ` · ${f.ref}` : ''} ({counts[f.id]})</option>
              ))}
            </optgroup>
          </select>
          {filter != null && <button className="btn sm quiet" onClick={() => traceStore.setFilter(null)}>Show all</button>}
        </div>
        <div className="tr-row tr-row-split">
          <div className="tr-lanes">{['Browser', 'Authenticator', 'API', 'Database'].map(l => <span key={l} className={`tr-lane ${l}`}>{l}</span>)}</div>
          <label className="tr-stepmode">
            Step through
            <button className="switch" role="switch" aria-checked={stepMode} aria-label="Step through"
                    onClick={() => traceStore.setStepMode(!stepMode)} />
          </label>
        </div>
      </div>
      <div className="tr-body">
        {activeFlow && <FlowSummary flow={activeFlow} entries={entries} />}
        {!entries.length && filter != null && <div className="tr-empty">No requests for this filter yet.</div>}
        {!all.length && (
          <div className="tr-empty">
            Every request you make now shows the security checks the server ran, with the real values.<br />
            Try signing in again, sending money or a Security Lab attack.
          </div>
        )}
        {entries.map(e => (
          <Request key={e.id} e={e} flow={flowById[e.flow]} filtered={filter === e.flow}
                   onFilter={id => traceStore.setFilter(id)}
                   expanded={expanded[e.id] ?? e.id === latest?.id}
                   limit={stepMode && e.id === latest?.id ? shown : null}
                   onToggle={() => setExpanded(x => ({ ...x, [e.id]: !(x[e.id] ?? e.id === latest?.id) }))} />
        ))}
      </div>
      <div className="tr-foot">
        <span className="tr-grow">
          {stepMode && latest ? `Step ${Math.min(shown, latest.steps.length)} of ${latest.steps.length}` : `${entries.length} request${entries.length === 1 ? '' : 's'}`}
        </span>
        <button className="btn sm" onClick={copy} disabled={!entries.length}><Icon.Copy size={16} />{copied ? 'Copied' : 'Markdown'}</button>
        {stepMode && latest && shown < latest.steps.length && (
          <button className="btn sm primary" onClick={() => setShown(n => n + 1)}>Next step <Icon.Play size={14} /></button>
        )}
      </div>
    </aside>
  )
}
