import React, { useEffect, useRef, useState } from 'react'
import { useTargetSelection, type Target } from '../api/targetSelection'
import { usePdfProgress } from '../hooks/usePdfProgress'
import TargetSwitcher from './TargetSwitcher'
import ScanResults from './ScanResults'

/* ── Engine routing ────────────────────────────────────────────── */

type ScanEngine = 'zap' | 'nmap'

function engineForTarget(t: Target | null): ScanEngine | null {
  if (!t) return null
  if (t.type === 'url') return 'zap'
  if (t.type === 'ip' || t.type === 'domain' || t.type === 'protocol') return 'nmap'
  return null
}

/* ── ZAP-specific types (preserved) ────────────────────────────── */

type ScanState = 'idle' | 'starting' | 'running' | 'done' | 'error'

interface ScanIds {
  target_url: string
  spider_id: string
  ascan_id: string
  zap_version: string
}

interface Alert {
  name: string
  risk: 'High' | 'Medium' | 'Low' | 'Informational' | string
  confidence: string
  url: string
  param: string
  evidence: string
  description: string
  cweid: string
  wascid: string
  solution: string
}

interface StatusResp {
  target_url: string
  spider_status: string | null
  ascan_status: string | null
  spider_urls: number
  num_alerts: number
  alerts: Alert[]
}

/* ── Helpers ────────────────────────────────────────────────────── */

const RISK_ORDER: Record<string, number> = { High: 3, Medium: 2, Low: 1, Informational: 0 }

function riskBadgeClass(risk: string): string {
  switch (risk) {
    case 'High': return 'badge badge-high'
    case 'Medium': return 'badge badge-medium'
    case 'Low': return 'badge badge-low'
    case 'Informational': return 'badge badge-info'
    default: return 'badge'
  }
}

function phaseStatus(status: string | undefined): 'pending' | 'running' | 'done' {
  if (status === 'done' || status === '100') return 'done'
  if (status === 'running') return 'running'
  return 'pending'
}

function fmtElapsed(secs: number): string {
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  if (h > 0) return `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`
  return `${m}:${s.toString().padStart(2, '0')}`
}

function phaseDesc(spiderPct: string | undefined, ascanPct: string | undefined): string {
  const sp = parseInt(spiderPct ?? '0', 10) || 0
  const ap = parseInt(ascanPct ?? '0', 10) || 0
  if (sp < 100) return '正在爬取站点页面…'
  if (ap < 100) return '正在检测漏洞…'
  return '正在汇总结果…'
}

/* ── Main component ────────────────────────────────────────────── */

export default function ZapScanPanel() {
  const { selected: activeTarget } = useTargetSelection('scan')
  const engine = engineForTarget(activeTarget)

  /* Core state */
  const [scanState, setScanState] = useState<ScanState>('idle')
  const [error, setError] = useState<string>('')

  /* ZAP-specific state */
  const [status, setStatus] = useState<StatusResp | null>(null)
  const [waitSpider, setWaitSpider] = useState(10)
  const [generatingPdf, setGeneratingPdf] = useState(false)
  const [pdfError, setPdfError] = useState<string>('')
  const pdfProgress = usePdfProgress(generatingPdf)

  /* ZAP scan IDs */
  const [scanIds, setScanIds] = useState<ScanIds | null>(null)

  /* Unified / Nmap state */
  const [scanId, setScanId] = useState<number | null>(null)
  const [phases, setPhases] = useState<Record<string, string> | null>(null)
  const [nmapResult, setNmapResult] = useState<any>(null)

  /* Elapsed timer */
  const [scanStartAt, setScanStartAt] = useState<number | null>(null)
  const [elapsed, setElapsed] = useState(0)

  /* Refs */
  const pollRef = useRef<number | null>(null)
  const pollFailRef = useRef(0)
  const finalizedRef = useRef(false)
  const prevTargetIdRef = useRef<number | null | undefined>(undefined)
  const POLL_FAIL_LIMIT = 3

  /* Stop polling on unmount */
  useEffect(() => {
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current)
    }
  }, [])

  /* Elapsed timer: ticks every second while scanning */
  useEffect(() => {
    if (scanStartAt === null) return
    const timer = window.setInterval(() => {
      setElapsed(Math.floor((Date.now() - scanStartAt) / 1000))
    }, 1000)
    return () => window.clearInterval(timer)
  }, [scanStartAt])

  /* Clear timer when scan stops */
  useEffect(() => {
    if (scanState === 'done' || scanState === 'error' || scanState === 'idle') {
      setScanStartAt(null)
    }
  }, [scanState])

  const stopPolling = () => {
    if (pollRef.current) {
      window.clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  const reset = () => {
    stopPolling()
    setScanState('idle')
    setError('')
    setStatus(null)
    setScanIds(null)
    setScanId(null)
    setPhases(null)
    setNmapResult(null)
    setScanStartAt(null)
    setElapsed(0)
  }

  /* Clear on target change (trap #29 semantics) */
  useEffect(() => {
    const curId = activeTarget?.id ?? null
    if (prevTargetIdRef.current === undefined) { prevTargetIdRef.current = curId; return }
    if (prevTargetIdRef.current === curId) return
    prevTargetIdRef.current = curId
    reset()
    window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
      detail: { source: 'scan', reset: true },
    }))
  }, [activeTarget?.id])

  /* ── startScan: unified API for all engines ── */

  const startScan = async () => {
    if (!activeTarget) return
    const eng = engine
    if (!eng) return

    setError('')
    setStatus(null)
    setScanIds(null)
    setScanId(null)
    setPhases(null)
    setNmapResult(null)
    setScanState('starting')
    setScanStartAt(Date.now())
    setElapsed(0)
    pollFailRef.current = 0
    finalizedRef.current = false

    /* Reset side-panel progress, mark target ready */
    window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
      detail: { source: 'scan', reset: true },
    }))
    window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
      detail: { source: 'scan', stepId: 'target', status: 'done' },
    }))
    window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
      detail: {
        source: 'scan',
        stepId: eng === 'zap' ? 'spider' : 'nmap',
        status: 'running',
      },
    }))

    try {
      if (eng === 'zap') {
        /* ── ZAP: use the existing specialized endpoint ── */
        const resp = await fetch('/api/tools/zap/scan', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_id: activeTarget.id,
            wait_spider_secs: waitSpider,
          }),
        })
        if (!resp.ok) {
          const e = await resp.json().catch(() => ({}))
          throw new Error(e.detail || `HTTP ${resp.status}`)
        }
        const data = await resp.json()
        setScanIds(data)
        setScanState('running')
        // Pass scanIds directly — React state update is async so pollZap would read stale null
        pollZapOnce(data)
        pollRef.current = window.setInterval(() => pollZapOnce(data), 2500)
      } else {
        /* ── Non-URL targets: unified scan API ── */
        const options: Record<string, any> = {}
        const resp = await fetch('/api/tools/scan', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target_id: activeTarget.id,
            options,
          }),
        })
        if (!resp.ok) {
          const e = await resp.json().catch(() => ({}))
          throw new Error(e.detail || `HTTP ${resp.status}`)
        }
        const data = await resp.json()
        setScanId(data.scan_id)
        setScanState('running')
        pollScan(data.scan_id)
        pollRef.current = window.setInterval(() => pollScan(data.scan_id), 2500)
      }
    } catch (err: any) {
      setError(err.message || String(err))
      setScanState('error')
    }
  }

  /* ── pollZapOnce: ZAP status polling (takes explicit ids to avoid React stale closure) ── */

  const pollZapOnce = async (s: ScanIds) => {
    if (!activeTarget) return
    try {
      const url = new URL('/api/tools/zap/scan/status', window.location.origin)
      url.searchParams.set('target_url', s.target_url)
      url.searchParams.set('spider_id', s.spider_id)
      url.searchParams.set('ascan_id', s.ascan_id)
      url.searchParams.set('include_alerts', 'true')
      url.searchParams.set('alert_limit', '1000')
      const resp = await fetch(url.toString(), { credentials: 'include' })
      if (!resp.ok) {
        if (resp.status >= 400 && resp.status < 500) {
          stopPolling()
          setError(`status HTTP ${resp.status}`)
          setScanState('error')
          return
        }
        pollFailRef.current += 1
        if (pollFailRef.current >= POLL_FAIL_LIMIT) {
          stopPolling()
          setError(`status HTTP ${resp.status} (${POLL_FAIL_LIMIT} 次连续失败)`)
          setScanState('error')
        }
        return
      }
      pollFailRef.current = 0
      const data: StatusResp = await resp.json()
      setStatus(data)
      const spiderDone = data.spider_status === '100'
      const ascanDone = data.ascan_status === '100'
      window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
        detail: { source: 'scan', stepId: 'spider', status: spiderDone ? 'done' : 'running' },
      }))
      if (spiderDone) {
        window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
          detail: { source: 'scan', stepId: 'ascan', status: ascanDone ? 'done' : 'running' },
        }))
      }
      if (ascanDone && spiderDone) {
        stopPolling()
        setScanState('done')
        window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
          detail: { source: 'scan', stepId: 'reporter', status: 'done' },
        }))
        if (!finalizedRef.current) {
          finalizedRef.current = true
          fetch('/api/tools/zap/finalize', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              target_url: s.target_url, target_id: activeTarget?.id ?? null,
              spider_id: s.spider_id, ascan_id: s.ascan_id,
            }),
          }).catch(() => { /* best-effort */ })
        }
      }
    } catch {
      pollFailRef.current += 1
      if (pollFailRef.current >= POLL_FAIL_LIMIT) {
        stopPolling()
        setError('轮询连接失败')
        setScanState('error')
      }
    }
  }

  /* ── pollScan: unified status polling ── */

  const pollScan = async (sid: number) => {
    try {
      const resp = await fetch(`/api/tools/scan/status?scan_id=${sid}`, {
        credentials: 'include',
      })
      if (!resp.ok) {
        /* 4xx = auth / scope / gone — stop immediately. */
        if (resp.status >= 400 && resp.status < 500) {
          stopPolling()
          setError(`status HTTP ${resp.status}`)
          setScanState('error')
          return
        }
        /* 5xx = transient — tolerate up to the limit. */
        pollFailRef.current += 1
        if (pollFailRef.current >= POLL_FAIL_LIMIT) {
          stopPolling()
          setError(`status HTTP ${resp.status} (${POLL_FAIL_LIMIT} 次连续失败)`)
          setScanState('error')
        }
        return
      }
      pollFailRef.current = 0
      const data = await resp.json()

      /* ── Phase / progress (both engines) ── */
      if (data.phases) setPhases(data.phases)

      /* ── ZAP-specific backward-compatible status ── */
      if (engine === 'zap') {
        setStatus(prev => ({
          target_url: data.target_url ?? prev?.target_url ?? '',
          spider_status:
            data.spider_status ?? data.phases?.spider ?? prev?.spider_status ?? null,
          ascan_status:
            data.ascan_status ?? data.phases?.ascan ?? prev?.ascan_status ?? null,
          num_alerts: data.num_alerts ?? prev?.num_alerts ?? 0,
          alerts: data.alerts ?? prev?.alerts ?? [],
        }))

        const spiderDone =
          (data.spider_status ?? data.phases?.spider) === '100'
        const ascanDone =
          (data.ascan_status ?? data.phases?.ascan) === '100'

        /* Side-panel events */
        window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
          detail: {
            source: 'scan',
            stepId: 'spider',
            status: spiderDone ? 'done' : 'running',
          },
        }))
        if (spiderDone) {
          window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
            detail: {
              source: 'scan',
              stepId: 'ascan',
              status: ascanDone ? 'done' : 'running',
            },
          }))
        }

        /* Both phases at 100 % → scan complete */
        if (ascanDone && spiderDone) {
          stopPolling()
          setScanState('done')
          window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
            detail: { source: 'scan', stepId: 'reporter', status: 'done' },
          }))
          /* Persist for admin review (once per scan). */
          if (!finalizedRef.current) {
            finalizedRef.current = true
            fetch('/api/tools/zap/finalize', {
              method: 'POST',
              credentials: 'include',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                target_url: data.target_url ?? '',
                target_id: activeTarget?.id ?? null,
                spider_id: data.spider_id ?? '',
                ascan_id: data.ascan_id ?? '',
              }),
            }).catch(() => {})
          }
          return
        }
      }

      /* ── Terminal state ── */
      if (data.status === 'done') {
        stopPolling()
        if (engine === 'nmap' && data.result) setNmapResult(data.result)
        setScanState('done')
        window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
          detail: { source: 'scan', stepId: 'reporter', status: 'done' },
        }))
      } else if (data.status === 'error') {
        /* For ZAP, errors are surfaced through the 5xx retry logic above;
           only surface explicit errors for non-ZAP engines here. */
        if (engine !== 'zap') {
          stopPolling()
          setError(data.error || '扫描失败')
          setScanState('error')
        }
      }
    } catch (err: any) {
      /* Network-level failure — also tolerate a few before failing. */
      pollFailRef.current += 1
      if (pollFailRef.current >= POLL_FAIL_LIMIT) {
        stopPolling()
        setError(err.message)
        setScanState('error')
      }
    }
  }

  /* ── ZAP-only: risk summary helpers ── */

  const riskCounts = (() => {
    const c = { High: 0, Medium: 0, Low: 0, Informational: 0 } as Record<string, number>
    for (const a of status?.alerts ?? []) {
      c[a.risk] = (c[a.risk] ?? 0) + 1
    }
    return c
  })()

  const sortedAlerts = [...(status?.alerts ?? [])].sort((a, b) => {
    const da = RISK_ORDER[a.risk] ?? -1
    const db = RISK_ORDER[b.risk] ?? -1
    if (da !== db) return db - da
    return a.name.localeCompare(b.name)
  })

  /* ── ZAP-only: PDF export ── */

  const exportPdf = async () => {
    if (!status || !activeTarget || generatingPdf) return
    setGeneratingPdf(true)
    setPdfError('')
    try {
      const md = buildScanMarkdown(activeTarget.value, status, sortedAlerts, riskCounts)
      const resp = await fetch('/api/reports/render-pdf', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: md,
          mode: 'x_scan',
          target_label: `#${activeTarget.id} ${activeTarget.value}`,
        }),
      })
      if (!resp.ok) {
        const errText = await resp.text().catch(() => '')
        throw new Error(`HTTP ${resp.status} · ${errText.slice(0, 200) || '上游错误'}`)
      }
      const blob = await resp.blob()
      const cd = resp.headers.get('Content-Disposition') || ''
      const m = /filename="([^"]+)"/.exec(cd)
      const now = new Date()
      const pad = (n: number) => n.toString().padStart(2, '0')
      const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`
                    + `-${pad(now.getHours())}${pad(now.getMinutes())}`
      const fallback = `x-scan-report-${stamp}.pdf`
      const filename = m ? m[1] : fallback
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err: any) {
      setPdfError(err?.message || '生成 PDF 失败')
    } finally {
      setGeneratingPdf(false)
    }
  }

  /* ═══════════════════════════════════════════════════════════════
     RENDER
     ═══════════════════════════════════════════════════════════════ */

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-3 sm:p-5">

      {/* ── Top card: target + controls ── */}
      <div className="card shrink-0 p-4 sm:p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-brand-text">渗透测试</h2>
            <p className="mt-1 text-xs text-brand-muted">
              对当前授权 URL/IP/域名等进行外部安全性渗透测试
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span className="status-dot status-dot-online" />
            <span className="text-brand-secondary">服务在线</span>
          </div>
        </div>

        {/* Target picker line */}
        <div className="mt-4 rounded-lg border border-brand-border bg-brand-bg2 p-3">
          <div className="mb-2 flex items-center justify-between gap-3">
            <span className="text-xs font-medium text-brand-secondary">扫描目标</span>
            <TargetSwitcher scope="scan"
              emptyHint="没有可扫描目标 — 请到 设置 → 目标配置 创建 url / ip / domain" />
          </div>

          {activeTarget ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-sm">
                  <span className="badge bg-brand-bg3 text-brand-secondary">
                    #{activeTarget.id}
                  </span>
                  <span className="badge badge-info">{activeTarget.type}</span>
                  <span className="font-mono text-brand-text">{activeTarget.value}</span>
                </div>
                {/* Engine badge */}
                {engine && (
                  <span className="rounded bg-brand-bg3 px-2 py-0.5 text-2xs text-brand-muted">
                    {engine === 'zap' ? 'Web 扫描' : '网络扫描'}
                  </span>
                )}
              </div>

              {/* Controls row: shown when not running */}
              {scanState !== 'running' && scanState !== 'starting' && (
                <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-brand-borderLight pt-3">
                  {/* Spider wait — only for URL / ZAP */}
                  {engine === 'zap' && (
                    <label className="flex items-center gap-2 text-xs text-brand-secondary">
                      <span>Spider 等待</span>
                      <input
                        type="number"
                        min={0}
                        max={120}
                        value={waitSpider}
                        onChange={e =>
                          setWaitSpider(
                            Math.max(0, Math.min(120, parseInt(e.target.value) || 0)),
                          )
                        }
                        className="w-16 rounded border border-brand-border bg-white px-2 py-1 text-right text-xs"
                      />
                      <span>秒</span>
                    </label>
                  )}
                  <button
                    onClick={startScan}
                    className="btn-primary flex items-center gap-2 px-4 py-1.5 text-sm"
                  >
                    <svg
                      className="h-4 w-4"
                      fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                    >
                      <path
                        strokeLinecap="round" strokeLinejoin="round"
                        d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.347a1.125 1.125 0 0 1 0 1.972l-11.54 6.347a1.125 1.125 0 0 1-1.667-.986V5.653Z"
                      />
                    </svg>
                    {engine === 'zap' ? '开始扫描' : '开始扫描'}
                  </button>
                  {scanState === 'done' && (
                    <button onClick={reset} className="btn-ghost text-xs">
                      清空结果
                    </button>
                  )}
                </div>
              )}
            </>
          ) : (
            <p className="text-sm text-brand-muted">
              请先到「设置 → 目标配置」创建并选定一个目标
            </p>
          )}
        </div>

        {/* ── Progress / status ── */}
        {(scanState === 'starting' || scanState === 'running') && engine === 'zap' && (
          <div className="mt-4 space-y-4">
            {/* Spider phase */}
            <div className="rounded-lg border border-brand-border bg-brand-bg2 p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-brand-text">🔎 站点爬取</span>
                <span className="text-xs text-brand-muted">
                  {status?.spider_status === '100' ? '✓ 完成' : '进行中…'}
                </span>
              </div>
              <ProgressBar
                label=""
                pct={status?.spider_status ?? phases?.spider ?? '0'}
              />
              <div className="mt-2 flex items-center gap-4 text-xs text-brand-muted">
                <span>已发现 <span className="text-brand-text font-medium">{status?.spider_urls ?? 0}</span> 个页面</span>
              </div>
            </div>

            {/* Active Scan phase */}
            <div className={`rounded-lg border border-brand-border bg-brand-bg2 p-4 ${(status?.spider_status ?? '0') !== '100' ? 'opacity-50' : ''}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-brand-text">⚔️ 漏洞扫描</span>
                <span className="text-xs text-brand-muted">
                  {(status?.spider_status ?? '0') !== '100' ? '等待爬取完成…' :
                   status?.ascan_status === '100' ? '✓ 完成' : '进行中…'}
                </span>
              </div>
              <ProgressBar
                label=""
                pct={(status?.spider_status ?? '0') !== '100' ? '0' : (status?.ascan_status ?? phases?.ascan ?? '0')}
              />
              <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-brand-muted">
                {status && status.num_alerts > 0 && (
                  <span>已发现 <span className="text-brand-warning font-medium">{status.num_alerts}</span> 个风险点</span>
                )}
              </div>
            </div>

            <div className="flex items-center justify-between text-xs text-brand-muted">
              <span>⏱ {fmtElapsed(elapsed)}</span>
              {scanId && <span>任务 #{scanId}</span>}
            </div>
          </div>
        )}

        {scanState === 'done' && engine === 'zap' && (
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <ProgressBar label={`站点爬取${status ? ` · ${status.spider_urls} 个页面` : ''}`} pct="100" />
            <ProgressBar label="漏洞扫描" pct="100" />
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-brand-muted sm:col-span-2">
              <div className="flex flex-wrap items-center gap-3">
                <span>✓ 已完成</span>
                <span className="text-brand-borderLight">|</span>
                <span>⏱ {fmtElapsed(elapsed)}</span>
                <span className="text-brand-borderLight">|</span>
                <span>共发现 {status?.num_alerts ?? 0} 个风险点</span>
              </div>
              {scanId && <span className="text-brand-muted">任务 #{scanId}</span>}
            </div>
          </div>
        )}

        {(scanState === 'starting' || scanState === 'running') && engine === 'nmap' && (
          <div className="mt-4 space-y-3">
            <PhaseBar label="端口发现" status={phaseStatus(phases?.phase1)} />
            <PhaseBar label="漏洞检测" status={phaseStatus(phases?.phase2)} />
            <PhaseBar label="威胁关联" status={phaseStatus(phases?.phase3)} />
            <div className="flex items-center justify-between text-xs text-brand-muted">
              <span>⏱ {fmtElapsed(elapsed)}</span>
              {scanId && <span>任务 #{scanId}</span>}
            </div>
          </div>
        )}

        {scanState === 'done' && engine === 'nmap' && (
          <div className="mt-4 space-y-3">
            <PhaseBar label="端口发现" status="done" />
            <PhaseBar label="漏洞检测" status="done" />
            <PhaseBar label="威胁关联" status="done" />
            <div className="flex items-center justify-between text-xs text-brand-muted">
              <span>✓ 已完成 · ⏱ {fmtElapsed(elapsed)}</span>
              {scanId && <span>任务 #{scanId}</span>}
            </div>
          </div>
        )}

        {scanState === 'error' && (
          <div className="mt-3 rounded-lg border border-brand-danger/40 bg-brand-dangerLight px-3 py-2 text-sm text-brand-danger">
            ✗ {error}
          </div>
        )}
      </div>

      {/* ── ZAP risk summary ── */}
      {engine === 'zap' && status && status.num_alerts > 0 && (
        <div className="card shrink-0 p-4 sm:p-5">
          <div className="mb-3 flex items-baseline justify-between">
            <h3 className="text-sm font-medium text-brand-text">风险概览</h3>
            <span className="text-xs text-brand-muted">{status.num_alerts} 条 alert</span>
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <RiskCard label="High" count={riskCounts.High} tone="danger" />
            <RiskCard label="Medium" count={riskCounts.Medium} tone="warning" />
            <RiskCard label="Low" count={riskCounts.Low} tone="success" />
            <RiskCard label="Informational" count={riskCounts.Informational} tone="info" />
          </div>
        </div>
      )}

      {/* ── ZAP alerts list ── */}
      {engine === 'zap' && status && status.alerts.length > 0 && (
        <div className="card flex flex-col">
          <div className="shrink-0 border-b border-brand-border bg-brand-bg2 px-4 py-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h3 className="text-sm font-medium text-brand-text">扫描结果 (按风险排序)</h3>
              <div className="flex items-center gap-2">
                {pdfError && !generatingPdf && (
                  <span className="text-2xs text-brand-danger">✗ {pdfError}</span>
                )}
                <button
                  type="button"
                  onClick={exportPdf}
                  disabled={generatingPdf}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-brand-primary bg-brand-primary px-3 py-1.5 text-xs font-medium text-white transition hover:bg-brand-primary/90 disabled:cursor-wait disabled:opacity-70"
                >
                  {generatingPdf ? (
                    <>
                      <svg className="h-3.5 w-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                      生成中…
                    </>
                  ) : (
                    <>
                      <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3" />
                      </svg>
                      导出 PDF
                    </>
                  )}
                </button>
              </div>
            </div>
            {generatingPdf && (
              <div className="mt-2.5">
                <div className="flex items-center justify-between text-xs text-brand-secondary">
                  <span className="truncate pr-2">
                    {pdfProgress.label}
                    <span className="mx-1.5 text-brand-muted">·</span>
                    已耗时 {(pdfProgress.elapsedMs / 1000).toFixed(1)}s
                    {pdfProgress.etaMs !== null && !pdfProgress.frozen && (
                      <>
                        <span className="mx-1.5 text-brand-muted">·</span>
                        约剩 {(pdfProgress.etaMs / 1000).toFixed(1)}s
                      </>
                    )}
                  </span>
                  <span className="shrink-0 tabular-nums text-brand-muted">
                    {pdfProgress.pct.toFixed(0)}%
                  </span>
                </div>
                <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-brand-border">
                  <div
                    className="h-full rounded-full bg-brand-primary transition-[width] duration-200 ease-out"
                    style={{ width: `${pdfProgress.pct}%` }}
                  />
                </div>
              </div>
            )}
          </div>
          <div className="divide-y divide-brand-borderLight">
            {sortedAlerts.map((a, i) => (
              <AlertRow key={i} alert={a} />
            ))}
          </div>
        </div>
      )}

      {/* ── Nmap results ── */}
      {engine === 'nmap' && nmapResult && (
        <ScanResults result={nmapResult} />
      )}

      {/* ── ZAP empty result ── */}
      {scanState === 'done' && engine === 'zap' && status?.num_alerts === 0 && (
        <div className="card p-6 text-center text-sm text-brand-muted">
          扫描完成,未发现 alert。
        </div>
      )}

      {/* ── Nmap empty result ── */}
      {scanState === 'done' && engine === 'nmap' && !nmapResult && (
        <div className="card p-6 text-center text-sm text-brand-muted">
          扫描完成,未发现开放端口或漏洞。
        </div>
      )}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════
   Sub-components
   ═══════════════════════════════════════════════════════════════════ */

function PhaseBar({ label, status }: { label: string; status: 'pending' | 'running' | 'done' }) {
  const colorClass =
    status === 'done'
      ? 'bg-emerald-500'
      : status === 'running'
        ? 'bg-brand-primary'
        : 'bg-brand-border'
  const pulseClass = status === 'running' ? 'animate-pulse' : ''
  const statusLabel =
    status === 'done' ? '✓ 完成' : status === 'running' ? '进行中…' : '等待'

  return (
    <div className="flex items-center gap-3 text-xs">
      <div className={`h-2 w-2 shrink-0 rounded-full ${colorClass} ${pulseClass}`} />
      <span className="text-brand-secondary">{label}</span>
      <span className="text-brand-muted">{statusLabel}</span>
    </div>
  )
}

function ProgressBar({ label, pct }: { label: string; pct: string }) {
  const n = Math.max(0, Math.min(100, parseInt(pct) || 0))
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between text-xs">
        <span className="text-brand-secondary">{label}</span>
        <span className="font-mono text-brand-text">{n}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-brand-bg3">
        <div
          className="h-full rounded-full bg-brand-primary transition-all duration-300"
          style={{ width: `${n}%` }}
        />
      </div>
    </div>
  )
}

function RiskCard({ label, count, tone }: {
  label: string
  count: number
  tone: 'danger' | 'warning' | 'success' | 'info'
}) {
  const toneClass = {
    danger: 'bg-brand-dangerLight text-brand-danger border-red-200',
    warning: 'bg-brand-warningLight text-brand-warning border-amber-200',
    success: 'bg-brand-successLight text-brand-success border-emerald-200',
    info: 'bg-brand-infoLight text-brand-info border-blue-200',
  }[tone]
  return (
    <div className={`rounded-lg border px-3 py-2 ${toneClass}`}>
      <div className="text-xs font-medium opacity-80">{label}</div>
      <div className="mt-1 font-mono text-xl font-semibold">{count}</div>
    </div>
  )
}

function AlertRow({ alert }: { alert: Alert }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="px-4 py-3 hover:bg-brand-bg2">
      <button onClick={() => setOpen(!open)} className="flex w-full items-start gap-3 text-left">
        <span className={`mt-0.5 shrink-0 ${riskBadgeClass(alert.risk)}`}>{alert.risk}</span>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline justify-between gap-2">
            <span className="truncate text-sm font-medium text-brand-text">{alert.name}</span>
            {alert.cweid && (
              <span className="shrink-0 font-mono text-2xs text-brand-muted">CWE-{alert.cweid}</span>
            )}
          </div>
          <div className="mt-1 truncate font-mono text-2xs text-brand-secondary">{alert.url}</div>
        </div>
        <svg
          className={`h-4 w-4 shrink-0 text-brand-muted transition-transform ${open ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
        </svg>
      </button>
      {open && (
        <div className="mt-3 space-y-2 rounded-lg bg-brand-bg2 p-3 text-xs">
          {alert.param && (
            <div>
              <span className="font-medium text-brand-secondary">参数:</span>{' '}
              <span className="font-mono text-brand-text">{alert.param}</span>
            </div>
          )}
          {alert.evidence && (
            <div>
              <span className="font-medium text-brand-secondary">证据:</span>{' '}
              <span className="font-mono break-all text-brand-text">{alert.evidence}</span>
            </div>
          )}
          {alert.description && (
            <div>
              <span className="font-medium text-brand-secondary">说明:</span>{' '}
              <span className="text-brand-text">{alert.description}</span>
            </div>
          )}
          {alert.solution && (
            <div>
              <span className="font-medium text-brand-secondary">建议:</span>{' '}
              <span className="text-brand-text">{alert.solution}</span>
            </div>
          )}
          <div className="flex gap-3 pt-1 text-2xs text-brand-muted">
            {alert.confidence && <span>置信度: {alert.confidence}</span>}
            {alert.wascid && <span>WASC-{alert.wascid}</span>}
          </div>
        </div>
      )}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════════
   Helpers: PDF Markdown generation (ZAP only)
   ═══════════════════════════════════════════════════════════════════ */

function mdEscape(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/`/g, '\\`')
}

function buildScanMarkdown(
  targetValue: string,
  status: StatusResp,
  alerts: Alert[],
  riskCounts: Record<string, number>,
): string {
  const lines: string[] = []
  lines.push(`## 扫描概览\n`)
  lines.push(`- **目标**: \`${targetValue}\``)
  lines.push(`- **告警总数**: ${status.num_alerts}`)
  lines.push(`- **Spider 进度**: ${status.spider_status ?? '-'}%`)
  lines.push(`- **Active Scan 进度**: ${status.ascan_status ?? '-'}%`)
  lines.push('')
  lines.push(`## 风险分布\n`)
  lines.push(`| 风险等级 | 数量 |`)
  lines.push(`|---|---:|`)
  lines.push(`| High | ${riskCounts.High ?? 0} |`)
  lines.push(`| Medium | ${riskCounts.Medium ?? 0} |`)
  lines.push(`| Low | ${riskCounts.Low ?? 0} |`)
  lines.push(`| Informational | ${riskCounts.Informational ?? 0} |`)
  lines.push('')
  lines.push(`## 详细告警 (按风险排序)\n`)
  if (alerts.length === 0) {
    lines.push('_未发现告警。_')
  } else {
    alerts.forEach((a, i) => {
      lines.push(`### ${i + 1}. [${a.risk}] ${mdEscape(a.name)}`)
      lines.push('')
      if (a.cweid) lines.push(`- **CWE**: CWE-${a.cweid}`)
      if (a.wascid) lines.push(`- **WASC**: WASC-${a.wascid}`)
      if (a.confidence) lines.push(`- **置信度**: ${a.confidence}`)
      if (a.url) lines.push(`- **URL**: \`${mdEscape(a.url)}\``)
      if (a.param) lines.push(`- **参数**: \`${mdEscape(a.param)}\``)
      if (a.evidence) lines.push(`- **证据**: \`${mdEscape(a.evidence)}\``)
      lines.push('')
      if (a.description) {
        lines.push(`**说明**`)
        lines.push('')
        lines.push(a.description)
        lines.push('')
      }
      if (a.solution) {
        lines.push(`**修复建议**`)
        lines.push('')
        lines.push(a.solution)
        lines.push('')
      }
    })
  }
  return lines.join('\n')
}
