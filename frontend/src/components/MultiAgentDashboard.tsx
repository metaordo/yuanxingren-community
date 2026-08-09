/**
 * MultiAgentDashboard — M3 production dashboard.
 *
 * Adds over M2: sticky SupervisorPanel, column folding, status filters,
 * second-round spawn highlight, multi-round decision history.
 *
 * Architecture: this component owns the WebSocket and the `runs` Map.
 * Subcomponents are pure presentation (props in, render out).
 */
import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useTargetSelection } from '../api/targetSelection'
import { TargetPicker } from './TargetPicker'
import { agentLabel } from '../api/agentLabels'

/** Broadcast a workflow-progress event to the global AgentWorkflow side panel. */
const emitProgress = (stepId: string, status: 'pending' | 'running' | 'done') => {
  window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
    detail: { source: 'multi_agent', stepId, status },
  }))
}
const emitProgressReset = () => {
  window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
    detail: { source: 'multi_agent', reset: true },
  }))
}

interface AgentRunState {
  run_id: number
  role: string
  status: 'pending' | 'running' | 'done' | 'failed' | 'skipped'
  scope_files_count?: number
  model?: string
  tokens_in?: number
  tokens_out?: number
  latency_ms?: number
  finding_count?: number
  findings: any[]
  transcript?: string
  error?: string
  round?: number       // which supervisor round produced this run (0 or 1)
  isNew?: boolean      // M3: flag for fresh second-round spawn highlight
}

interface SupervisorDecision {
  round: number
  picked: { role: string; scope_files: string[]; hints?: any }[]
  rejected: { role: string; why_skipped: string }[]
  rationale: string
}

interface VerifierStats {
  raw: number
  after_l1?: number
  after_l2?: number
  after_l3?: number
  after_dedupe: number
  clusters: number
}

interface UnknownReport {
  finding_idx: number
  novelty?: { value: number; rationale: string; similar_refs?: string[] }
  poc_source?: string
  poc_language?: string
  sandbox_triggered?: boolean
  sandbox_exit_code?: number
  sandbox_stdout?: string
  sandbox_stderr?: string
  disclosure_body?: string
  disclosure_embargo_until?: string
}

type FilterMode = 'all' | 'with-findings' | 'running'

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/40',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
  medium: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
  low: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
  info: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
}

const STATUS_DOT: Record<string, string> = {
  pending: 'bg-brand-muted',
  running: 'bg-brand-primary animate-pulse',
  done: 'bg-brand-success',
  failed: 'bg-brand-danger',
  skipped: 'bg-brand-muted opacity-50',
}

export default function MultiAgentDashboard() {
  const { targets, selected, select } = useTargetSelection('multi_agent')
  const selectedTargetId = selected?.id ?? null
  const setSelectedTargetId = (id: number | null) => {
    if (id === null) {
      select(null)
    } else {
      const t = targets.find(x => x.id === id)
      if (t) select(t)
    }
  }
  const [prompt, setPrompt] = useState('对该项目做一次完整的安全审计')
  const [busy, setBusy] = useState(false)
  const [taskId, setTaskId] = useState<number | null>(null)
  const [decisions, setDecisions] = useState<SupervisorDecision[]>([])
  const [runs, setRuns] = useState<Map<number, AgentRunState>>(new Map())
  const [report, setReport] = useState<string>('')
  const [verifiedFindings, setVerifiedFindings] = useState<any[]>([])
  const [stats, setStats] = useState<VerifierStats | null>(null)
  const [unknownReports, setUnknownReports] = useState<Map<number, UnknownReport>>(new Map())
  const [zerodayActive, setZerodayActive] = useState(false)
  const [error, setError] = useState<string>('')
  const [filter, setFilter] = useState<FilterMode>('all')
  const wsRef = useRef<WebSocket | null>(null)
  const currentRoundRef = useRef<number>(0)

  useEffect(() => () => { wsRef.current?.close() }, [])

  // (mode sync moved to Dashboard.tsx — this component now stays mounted
  // across nav switches, so a mount-time effect can't reliably re-set mode.)

  const clearLocalResults = () => {
    setDecisions([])
    setRuns(new Map())
    setReport('')
    setVerifiedFindings([])
    setStats(null)
    setUnknownReports(new Map())
    setZerodayActive(false)
    setTaskId(null)
    setError('')
    emitProgressReset()
    window.dispatchEvent(new CustomEvent('pa:findings', {
      detail: { source: 'multi_agent', findings: [] },
    }))
  }

  // When THIS panel's effective selection transitions from a real source
  // target back to none — meaning the user picked "暂不选择" or the active
  // source target was deleted — clean up local panel state so the last run's
  // SupervisorPanel / verified findings / report card don't dangle.
  // Selections made elsewhere (url/ip on Scan/Chat tabs) don't trigger this.
  const prevSelectedRef = useRef<number | null>(selectedTargetId)
  useEffect(() => {
    const prev = prevSelectedRef.current
    if (selectedTargetId === null && prev !== null) {
      clearLocalResults()
    }
    prevSelectedRef.current = selectedTargetId
  }, [selectedTargetId])

  const deleteCurrentTarget = async () => {
    if (selectedTargetId === null || busy) return
    const tgt = targets.find(t => t.id === selectedTargetId)
    if (!tgt) return
    if (!window.confirm(`确认删除目标 #${tgt.id}（${tgt.value}）？\n该操作只移除目标记录,上传文件本体保留。`)) return
    await doDelete(tgt.id)
  }

  const doDelete = async (id: number) => {
    try {
      const resp = await fetch(`/targets/${id}`, {
        method: 'DELETE',
        credentials: 'include',
      })
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}))
        setError(data.detail || '删除失败')
        return
      }
      if (selectedTargetId === id) {
        setSelectedTargetId(null)
      }
      window.dispatchEvent(new CustomEvent('pa:target_deleted', { detail: { id } }))
      emitProgressReset()
    } catch (e: any) {
      setError(e.message || '删除失败')
    }
  }

  const updateRun = (run_id: number, mut: (r: AgentRunState) => AgentRunState) => {
    setRuns(prev => {
      const next = new Map(prev)
      const cur = next.get(run_id) || {
        run_id, role: '?', status: 'pending', findings: [],
      }
      next.set(run_id, mut(cur))
      return next
    })
  }

  const start = () => {
    if (!selectedTargetId || busy) return
    setBusy(true)
    setError('')
    setDecisions([])
    setRuns(new Map())
    setReport('')
    setVerifiedFindings([])
    setStats(null)
    setUnknownReports(new Map())
    setZerodayActive(false)
    setTaskId(null)
    currentRoundRef.current = 0
    // Reset the side-panel pipeline visualization for this new run, then
    // immediately mark supervisor as running. The backend only yields
    // `workflow_started` *after* supervisor_pick() returns (a 5-10s LLM
    // call), so without this client-side seed the user would never see
    // the spinner during the longest single phase of the run.
    emitProgressReset()
    emitProgress('supervisor', 'running')

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${window.location.host}/api/chat/stream`)
    wsRef.current = ws

    ws.onopen = () => {
      ws.send(JSON.stringify({
        message: prompt,
        target_id: selectedTargetId,
        mode: 'multi_agent',
        upload_ids: [],
      }))
    }
    ws.onmessage = (ev) => {
      let evt: any
      try { evt = JSON.parse(ev.data) } catch { return }
      switch (evt.event) {
        case 'workflow_started':
          setTaskId(evt.task_id)
          emitProgress('supervisor', 'running')
          break
        case 'supervisor_decision': {
          const decision: SupervisorDecision = {
            round: evt.round, picked: evt.picked,
            rejected: evt.rejected, rationale: evt.rationale,
          }
          setDecisions(prev => [...prev, decision])
          currentRoundRef.current = evt.round
          // Supervisor is "done" after any decision (further rounds keep it
          // green); workers start spinning as soon as we've got picks.
          emitProgress('supervisor', 'done')
          if ((evt.picked || []).length > 0) {
            emitProgress('workers', 'running')
          }
          break
        }
        case 'agent_started':
          updateRun(evt.run_id, _ => ({
            run_id: evt.run_id,
            role: evt.role,
            status: 'running',
            scope_files_count: evt.scope_files_count,
            model: evt.model,
            findings: [],
            round: currentRoundRef.current,
            isNew: currentRoundRef.current === 1,
          }))
          // remove `isNew` flag after 2 seconds so the highlight fades
          if (currentRoundRef.current === 1) {
            setTimeout(() => {
              updateRun(evt.run_id, r => ({ ...r, isNew: false }))
            }, 2000)
          }
          break
        case 'agent_finding':
          updateRun(evt.run_id, r => ({
            ...r, findings: [...r.findings, evt.finding],
          }))
          break
        case 'agent_transcript':
          updateRun(evt.run_id, r => ({ ...r, transcript: evt.transcript }))
          break
        case 'agent_done':
          updateRun(evt.run_id, r => ({
            ...r, status: 'done',
            tokens_in: evt.tokens_in, tokens_out: evt.tokens_out,
            latency_ms: evt.latency_ms,
            model: evt.model || r.model,
            finding_count: evt.finding_count,
          }))
          break
        case 'agent_failed':
          updateRun(evt.run_id, r => ({
            ...r, status: 'failed', error: evt.error,
            latency_ms: evt.latency_ms,
          }))
          break
        case 'verifier_dedupe':
          setStats(evt.stats)
          // Workers are guaranteed finished by the time verifier runs.
          emitProgress('workers', 'done')
          emitProgress('verifier', 'done')
          emitProgress('verifier_reviewer', 'running')
          break
        case 'verifier_reviewer_done':
          emitProgress('verifier_reviewer', 'done')
          emitProgress('reporter', 'running')
          break
        case 'unknown_pipeline_started':
          setZerodayActive(true)
          break
        case 'unknown_pipeline_skipped':
        case 'unknown_pipeline_done':
          setZerodayActive(false)
          break
        case 'novelty_scored':
        case 'poc_synthesized':
        case 'sandbox_result':
        case 'disclosure_drafted': {
          const idx = evt.finding_idx
          setUnknownReports(prev => {
            const next = new Map(prev)
            const cur = next.get(idx) || { finding_idx: idx }
            if (evt.event === 'novelty_scored') {
              cur.novelty = {
                value: evt.novelty,
                rationale: evt.rationale,
              }
            } else if (evt.event === 'poc_synthesized') {
              cur.poc_source = evt.source_preview
              cur.poc_language = evt.language
            } else if (evt.event === 'sandbox_result') {
              cur.sandbox_triggered = evt.triggered
              cur.sandbox_exit_code = evt.exit_code
              cur.sandbox_stdout = evt.stdout_preview
              cur.sandbox_stderr = evt.stderr_preview
            } else if (evt.event === 'disclosure_drafted') {
              cur.disclosure_body = evt.body_preview
              cur.disclosure_embargo_until = evt.embargo_until
            }
            next.set(idx, cur)
            return next
          })
          break
        }
        case 'workflow_done':
          setReport(evt.report || '')
          setVerifiedFindings(evt.findings || [])
          setStats(evt.stats || null)
          if (Array.isArray(evt.unknown_reports)) {
            // bulk-replace with the final, authoritative state from backend
            const m = new Map<number, UnknownReport>()
            for (const r of evt.unknown_reports) {
              m.set(r.finding_idx, r as UnknownReport)
            }
            setUnknownReports(m)
          }
          emitProgress('reporter', 'done')
          // Legacy bus: keep older consumers (AttackGraph, etc.) working.
          window.dispatchEvent(new CustomEvent('pa:findings', {
            detail: { source: 'multi_agent', findings: evt.findings || [] },
          }))
          // Expose the final report markdown for download via the side panel.
          if (typeof evt.report === 'string' && evt.report.trim()) {
            window.dispatchEvent(new CustomEvent('pa:report_available', {
              detail: { source: 'multi_agent', content: evt.report, mode: 'multi_agent' },
            }))
          }
          setBusy(false)
          break
        case 'workflow_error':
          setError(evt.detail || 'workflow error')
          setBusy(false)
          break
      }
    }
    ws.onerror = () => { setError('WebSocket connection failed'); setBusy(false) }
    ws.onclose = () => { setBusy(false) }
  }

  const stop = () => { wsRef.current?.close(); setBusy(false) }

  const filteredRuns = useMemo(() => {
    const list = Array.from(runs.values()).sort((a, b) => a.run_id - b.run_id)
    if (filter === 'with-findings') return list.filter(r => r.findings.length > 0)
    if (filter === 'running') return list.filter(r => r.status === 'running')
    return list
  }, [runs, filter])

  const runCount = runs.size
  const filteredCount = filteredRuns.length

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-3 sm:p-5">
      {/* Header: target + prompt + start */}
      <div className="card p-4 sm:p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-brand-text">多 Agent 并行审计</h2>
            <p className="mt-1 text-xs text-brand-muted">
              Supervisor 调度 8 个专项分析引擎 · 三层去重 · 二次深挖
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className={`status-dot ${busy ? 'status-dot-online' : ''}`} />
            <span className="text-brand-secondary">{busy ? '运行中' : '空闲'}</span>
            {taskId !== null && (
              <span className="font-mono text-2xs text-brand-muted">task #{taskId}</span>
            )}
          </div>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <label className="text-xs text-brand-secondary">源代码目标:</label>
          <TargetPicker
            targets={targets}
            selectedId={selectedTargetId}
            disabled={busy}
            onSelect={id => setSelectedTargetId(id)}
            onDelete={async id => {
              const tgt = targets.find(t => t.id === id)
              if (!tgt) return
              if (!window.confirm(`确认删除目标 #${tgt.id}（${tgt.value}）？\n该操作只移除目标记录,上传文件本体保留。`)) return
              await doDelete(id)
            }}
          />
        </div>
        <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center">
          <input
            type="text" value={prompt}
            onChange={e => setPrompt(e.target.value)}
            disabled={busy}
            placeholder="审计目标(给 supervisor 的指令)"
            className="flex-1 rounded border border-brand-border bg-white px-3 py-2 text-sm"
          />
          {busy ? (
            <button onClick={stop} className="btn-ghost text-sm">中断</button>
          ) : (
            <button onClick={start} disabled={!selectedTargetId}
              className="btn-primary px-4 py-2 text-sm disabled:opacity-50">
              开始审计
            </button>
          )}
        </div>
        {error && (
          <div className="mt-3 rounded-lg border border-brand-danger/40 bg-brand-dangerLight px-3 py-2 text-sm text-brand-danger">
            ✗ {error}
          </div>
        )}
      </div>

      {/* Sticky SupervisorPanel — shows all rounds */}
      {decisions.length > 0 && (
        <SupervisorPanel decisions={decisions} />
      )}

      {/* Verifier stats */}
      {stats && (
        <div className="card p-3 sm:p-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 className="text-sm font-medium text-brand-text">交叉验证摘要</h3>
            <div className="flex gap-3 text-xs text-brand-secondary">
              <span>原始 <span className="font-mono text-brand-text">{stats.raw}</span></span>
              {stats.after_l1 !== undefined && (
                <span>L1 <span className="font-mono text-brand-text">{stats.after_l1}</span></span>
              )}
              {stats.after_l2 !== undefined && (
                <span>L2 <span className="font-mono text-brand-text">{stats.after_l2}</span></span>
              )}
              <span>已确认 <span className="font-mono text-brand-success">{stats.after_dedupe}</span></span>
            </div>
          </div>
        </div>
      )}

      {/* Agent grid controls */}
      {runCount > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-2 px-1">
          <h3 className="text-sm font-medium text-brand-text">
            Agent 运行 <span className="text-brand-muted">({filteredCount}/{runCount})</span>
          </h3>
          <div className="flex items-center gap-1 text-xs">
            <FilterChip active={filter === 'all'} onClick={() => setFilter('all')}>全部</FilterChip>
            <FilterChip active={filter === 'running'} onClick={() => setFilter('running')}>运行中</FilterChip>
            <FilterChip active={filter === 'with-findings'} onClick={() => setFilter('with-findings')}>仅有发现</FilterChip>
          </div>
        </div>
      )}

      {/* Agent columns grid */}
      {filteredRuns.length > 0 && (
        <div
          className="grid gap-3"
          style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}
        >
          {filteredRuns.map(r => <AgentColumn key={r.run_id} run={r} />)}
        </div>
      )}

      {/* Final report */}
      {report && (
        <div className="card p-4 sm:p-5">
          <h3 className="mb-3 text-sm font-medium text-brand-text">最终报告</h3>
          <pre className="whitespace-pre-wrap break-words font-mono text-xs text-brand-text">
            {report}
          </pre>
        </div>
      )}

      {/* Verified findings (post-dedupe) */}
      {verifiedFindings.length > 0 && (
        <div className="card p-4 sm:p-5">
          <h3 className="mb-3 text-sm font-medium text-brand-text">
            已确认漏洞 ({verifiedFindings.length})
          </h3>
          <div className="space-y-2">
            {verifiedFindings.map((f, i) => (
              <FindingCard key={i} finding={f} />
            ))}
          </div>
        </div>
      )}

      {/* 0-Day pipeline section (M4) */}
      {(zerodayActive || unknownReports.size > 0) && (
        <ZeroDayPanel
          reports={unknownReports}
          verified={verifiedFindings}
          active={zerodayActive}
        />
      )}
    </div>
  )
}


function FilterChip({ active, onClick, children }: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full px-3 py-1 transition-colors ${
        active
          ? 'bg-brand-primary text-white'
          : 'bg-brand-bg3 text-brand-secondary hover:bg-brand-border'
      }`}
    >
      {children}
    </button>
  )
}


function SupervisorPanel({ decisions }: { decisions: SupervisorDecision[] }) {
  // Default: collapse all but the most recent decision — on small displays the
  // full rationale + picked/rejected badges from multiple rounds can easily
  // occupy 2/3 of the viewport, hiding the agent grid and final report below.
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set())
  useEffect(() => {
    if (decisions.length > 1) {
      // Auto-collapse everything except the latest round whenever a new round arrives.
      const next = new Set<number>()
      for (let i = 0; i < decisions.length - 1; i++) next.add(i)
      setCollapsed(next)
    }
  }, [decisions.length])

  const toggle = (i: number) => {
    setCollapsed(prev => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      return next
    })
  }

  const allCollapsed = decisions.length > 0 && decisions.every((_, i) => collapsed.has(i))
  const collapseAll = () => setCollapsed(new Set(decisions.map((_, i) => i)))
  const expandAll = () => setCollapsed(new Set())

  return (
    <div className="card p-4 sticky top-0 z-10 bg-white/95 backdrop-blur-sm">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="text-sm font-medium text-brand-text">Supervisor 决策历史</h3>
        {decisions.length > 0 && (
          <button
            type="button"
            onClick={allCollapsed ? expandAll : collapseAll}
            className="text-2xs text-brand-secondary hover:text-brand-primary transition-colors"
          >
            {allCollapsed ? '全部展开' : '全部折叠'}
          </button>
        )}
      </div>
      <div className="space-y-2">
        {decisions.map((d, i) => {
          const isCollapsed = collapsed.has(i)
          return (
            <div key={i} className={`rounded-lg border ${
              d.round === 0
                ? 'border-brand-border bg-brand-bg2'
                : 'border-brand-info/40 bg-brand-infoLight'
            }`}>
              <button
                type="button"
                onClick={() => toggle(i)}
                className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left hover:bg-black/[0.02] transition-colors rounded-lg"
                aria-expanded={!isCollapsed}
              >
                <span className="flex items-center gap-2 min-w-0">
                  <svg className={`h-3 w-3 shrink-0 text-brand-muted transition-transform ${isCollapsed ? '' : 'rotate-90'}`}
                       fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5" />
                  </svg>
                  <span className="text-xs font-medium text-brand-secondary">
                    {d.round === 0 ? '初始调度' : `第 ${d.round + 1} 轮 · 深度追加`}
                  </span>
                  {isCollapsed && (
                    <span className="text-2xs text-brand-muted truncate">
                      · {d.picked.length} 选 / {d.rejected.length} 拒
                    </span>
                  )}
                </span>
                {d.round > 0 && (
                  <span className="shrink-0 text-2xs text-brand-info">+{d.picked.length} 追加</span>
                )}
              </button>

              {!isCollapsed && (
                <div className="px-3 pb-3">
                  <p className="mb-2 text-xs text-brand-secondary">{d.rationale}</p>
                  <div className="flex flex-wrap gap-1.5">
                    {d.picked.map(p => (
                      <span key={p.role}
                            className={`badge ${d.round > 0 ? 'badge-info' : 'bg-brand-bg3 text-brand-text border border-brand-border'}`}>
                        ✓ {agentLabel(p.role)}
                        <span className="ml-1 opacity-60">({p.scope_files.length})</span>
                      </span>
                    ))}
                    {d.rejected.slice(0, 5).map(r => (
                      <span key={r.role} className="badge bg-brand-bg3 text-brand-muted"
                            title={r.why_skipped}>
                        ✗ {agentLabel(r.role)}
                      </span>
                    ))}
                    {d.rejected.length > 5 && (
                      <span className="text-2xs text-brand-muted self-center">
                        +{d.rejected.length - 5} 已拒
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}


export function AgentColumn({ run }: { run: AgentRunState }) {
  const isVerifier = run.role === 'verifier-reviewer'
  const ringClass = run.isNew
    ? 'ring-2 ring-brand-info ring-offset-2 ring-offset-brand-bg2 transition-all'
    : ''
  const isFolded = run.status === 'done' && run.findings.length === 0
  return (
    <div className={`card flex flex-col overflow-hidden ${ringClass} ${
      isFolded ? 'min-h-[100px]' : 'h-[480px]'
    } ${isVerifier ? 'border-l-4 border-l-gray-400 bg-gray-50' : ''}`}>
      <div className="border-b border-brand-border bg-brand-bg2 px-3 py-2">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <span className={`h-2 w-2 shrink-0 rounded-full ${STATUS_DOT[run.status] || 'bg-brand-muted'}`} />
            <span className="truncate text-sm font-medium text-brand-text">
              {isVerifier ? '🔍 ' : ''}{agentLabel(run.role)}
            </span>
            {run.round === 1 && (
              <span className="badge badge-info text-2xs px-1.5 py-0">R2</span>
            )}
          </div>
          <span className="font-mono text-2xs text-brand-muted">#{run.run_id}</span>
        </div>
        <div className="mt-1 flex flex-wrap gap-2 text-2xs text-brand-muted">
          <span>{run.status}</span>
          {run.scope_files_count !== undefined && <span>· {run.scope_files_count} 文件</span>}
          {run.latency_ms !== undefined && <span>· {(run.latency_ms / 1000).toFixed(1)}s</span>}
          {(run.tokens_in !== undefined || run.tokens_out !== undefined) && (
            <span>· {run.tokens_in ?? 0}/{run.tokens_out ?? 0} tok</span>
          )}
          {isVerifier && run.findings.length > 0 && (
            <span>· 复查 {run.findings.length} 条</span>
          )}
        </div>
      </div>

      {!isFolded && (
        <div className="flex-1 overflow-y-auto p-2">
          {run.findings.length === 0 && run.status === 'running' && (
            <div className="text-center text-xs text-brand-muted py-6">分析中…</div>
          )}
          {run.findings.length === 0 && run.status === 'failed' && (
            <div className="rounded border border-brand-danger/40 bg-brand-dangerLight p-2 text-xs text-brand-danger">
              ✗ {run.error || '失败'}
            </div>
          )}
          {run.findings.length === 0 && run.status === 'skipped' && (
            <div className="text-center text-xs text-brand-muted py-6">已跳过</div>
          )}
          <div className="space-y-2">
            {run.findings.map((f, i) => <FindingCard key={i} finding={f} compact />)}
          </div>
        </div>
      )}

      {run.transcript && !isFolded && (
        <details className="border-t border-brand-border bg-brand-bg2 px-3 py-2 text-2xs text-brand-muted">
          <summary className="cursor-pointer">原始 transcript</summary>
          <pre className="mt-2 max-h-32 overflow-y-auto whitespace-pre-wrap break-words text-brand-secondary">
            {run.transcript.slice(0, 4000)}
          </pre>
        </details>
      )}
    </div>
  )
}


function FindingCard({ finding, compact = false }: { finding: any; compact?: boolean }) {
  const sev = (finding.severity || 'low').toLowerCase()
  const sevClass = SEVERITY_BADGE[sev] || SEVERITY_BADGE.low
  // M3: support both single-file and pattern (locations[]) representations
  let location = ''
  if (Array.isArray(finding.locations) && finding.locations.length) {
    location = finding.locations.slice(0, 4).join(', ')
    if (finding.locations.length > 4) location += ` … (+${finding.locations.length - 4})`
  } else if (finding.file) {
    location = finding.file + (finding.line ? `:${finding.line}` : '')
  }
  return (
    <div className="rounded-lg border border-brand-border bg-brand-bg p-2">
      <div className="flex items-start gap-2">
        <span className={`shrink-0 rounded border px-1.5 py-0.5 text-2xs font-semibold uppercase ${sevClass}`}>
          {sev}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline justify-between gap-2">
            <div className="text-sm font-medium text-brand-text">
              {finding.title || '(untitled)'}
            </div>
            {finding.cwe && (
              <span className="shrink-0 font-mono text-2xs text-brand-muted">{finding.cwe}</span>
            )}
          </div>
          {location && (
            <div className="mt-0.5 truncate font-mono text-2xs text-brand-secondary">
              {location}
            </div>
          )}
          {finding.pattern_hits && finding.pattern_hits > 1 && (
            <div className="mt-1 text-2xs text-brand-warning">
              ★ 模式发现:{finding.pattern_hits} 处命中
            </div>
          )}
          {!compact && finding.rationale && (
            <div className="mt-2 text-xs text-brand-secondary">{finding.rationale}</div>
          )}
          {!compact && finding.evidence && (
            <pre className="mt-2 overflow-x-auto rounded bg-brand-bg2 p-2 font-mono text-2xs">
              {String(finding.evidence).slice(0, 400)}
            </pre>
          )}
          {finding.corroborating_roles && finding.corroborating_roles.length > 1 && (
            <div className="mt-1 text-2xs text-brand-info">
              ✓ {finding.corroborating_roles.length} agent 协同确认
            </div>
          )}
        </div>
      </div>
    </div>
  )
}


function ZeroDayPanel({
  reports, verified, active,
}: {
  reports: Map<number, UnknownReport>
  verified: any[]
  active: boolean
}) {
  const sorted = Array.from(reports.values())
    .sort((a, b) => (b.novelty?.value || 0) - (a.novelty?.value || 0))
  return (
    <div className="card p-4 sm:p-5 border-l-4 border-l-brand-primary">
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h3 className="text-sm font-medium text-brand-text">
          🔬 0-Day 深挖管线 {active && <span className="ml-2 text-xs text-brand-primary animate-pulse">运行中…</span>}
        </h3>
        <span className="text-xs text-brand-muted">{reports.size} 候选</span>
      </div>
      <div className="space-y-3">
        {sorted.map((r) => (
          <ZeroDayCard key={r.finding_idx} report={r} verified={verified} />
        ))}
        {sorted.length === 0 && active && (
          <div className="text-center text-xs text-brand-muted py-4">
            评估 high+ findings 的新颖度…
          </div>
        )}
      </div>
    </div>
  )
}


function ZeroDayCard({
  report, verified,
}: {
  report: UnknownReport
  verified: any[]
}) {
  const novelty = report.novelty?.value ?? 0
  const isCandidate = novelty >= 0.7
  const refFinding = verified[report.finding_idx]
  const tone = isCandidate
    ? 'border-red-500/40 bg-red-500/5'
    : novelty >= 0.4
    ? 'border-amber-500/40 bg-amber-500/5'
    : 'border-brand-border bg-brand-bg2'
  return (
    <div className={`rounded-lg border ${tone} p-3`}>
      <div className="flex items-baseline justify-between gap-2">
        <div className="text-sm font-medium text-brand-text">
          {isCandidate ? '🔴 候选 0-Day' : novelty >= 0.4 ? '🟡 中等新颖度' : '🟢 已知模式'}
          <span className="ml-2 text-xs text-brand-muted">finding #{report.finding_idx + 1}</span>
        </div>
        <span className="font-mono text-2xs text-brand-secondary">
          novelty {novelty.toFixed(2)}
        </span>
      </div>
      {refFinding && (
        <div className="mt-1 truncate text-xs text-brand-secondary">
          {refFinding.title}
        </div>
      )}
      {report.novelty?.rationale && (
        <div className="mt-2 text-xs text-brand-secondary">
          <span className="font-medium">理由:</span> {report.novelty.rationale}
        </div>
      )}

      {report.poc_source && (
        <details className="mt-3">
          <summary className="cursor-pointer text-xs text-brand-info">
            ▸ PoC ({report.poc_language || 'python'})
          </summary>
          <pre className="mt-2 overflow-x-auto rounded bg-brand-bg2 p-2 font-mono text-2xs">
            {report.poc_source.slice(0, 1500)}
          </pre>
        </details>
      )}

      {report.sandbox_triggered !== undefined && (
        <div className="mt-3 rounded border border-brand-border bg-brand-bg p-2 text-xs">
          <div className="flex items-center gap-2">
            <span className={report.sandbox_triggered
              ? 'text-brand-danger font-medium'
              : 'text-brand-muted'}>
              {report.sandbox_triggered ? '✓ 沙箱触发' : '✗ 沙箱未触发'}
            </span>
            <span className="text-2xs text-brand-muted">
              exit={report.sandbox_exit_code}
            </span>
          </div>
          {report.sandbox_stderr && (
            <pre className="mt-1 overflow-x-auto font-mono text-2xs text-brand-secondary">
              {report.sandbox_stderr.slice(0, 300)}
            </pre>
          )}
        </div>
      )}

      {report.disclosure_body && (
        <details className="mt-3">
          <summary className="cursor-pointer text-xs text-brand-info">
            ▸ 披露草稿
            {report.disclosure_embargo_until && (
              <span className="ml-2 text-2xs text-brand-muted">
                禁运至 {new Date(report.disclosure_embargo_until).toLocaleDateString()}
              </span>
            )}
          </summary>
          <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded bg-brand-bg2 p-2 font-mono text-2xs">
            {report.disclosure_body.slice(0, 1500)}
          </pre>
        </details>
      )}
    </div>
  )
}
