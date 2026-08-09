import { useEffect, useRef, useState } from 'react'
import { useTargetSelection } from '../api/targetSelection'
import { TargetPicker } from './TargetPicker'

type ScanState = 'idle' | 'running' | 'done' | 'error'

const SINK_LABELS: Record<string, string> = {
  rce: '远程代码执行 (RCE)',
  sqli: 'SQL 注入 (SQLi)',
  ssti: '模板注入 (SSTI)',
  id: '通用危险调用 (ID)',
}
const SINK_COLOR: Record<string, string> = {
  rce: 'text-red-500',
  sqli: 'text-orange-500',
  ssti: 'text-amber-500',
  id: 'text-blue-500',
}

interface PathItem {
  path_key: string
  path: string
  middles: { method: string; short_method: string; filename: string; call_line: number }[]
  taints: number
}
interface DetailPath {
  path: string
  dynamic_success: boolean
  prompt: string | null
  channel_mutations: string[] | null
  chat_interaction: { role: string; content: string }[] | null
  dynamic_path: string | null
}
interface SinkStatus {
  total: number
  running: boolean
  counts: { success: number; failed: number; running: number; queued: number; not_run: number }
  paths: { path_key: string; path: string; status: string }[]
}
interface ScanResult {
  id: number
  status: string
  sink_rules: string[]
  cuscuta_project: string | null
  verified_success?: number
  total_executed?: number
  paths_by_sink?: Record<string, { total_paths: number; risk_paths_with_middles: number; paths: PathItem[] }>
  detail_by_sink?: Record<string, { count: number; paths: DetailPath[] }>
  sink_status?: Record<string, SinkStatus>
  error?: string
}

export default function AgentAuditPanel() {
  const { targets, selected, select } = useTargetSelection('agent_audit')
  const [state, setState] = useState<ScanState>('idle')
  const [scanId, setScanId] = useState<number | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [elapsed, setElapsed] = useState(0)
  const [expandedPath, setExpandedPath] = useState<string | null>(null)
  const [activeSink, setActiveSink] = useState<string>('rce')
  const pollRef = useRef<number | null>(null)

  useEffect(() => () => { if (pollRef.current) window.clearInterval(pollRef.current) }, [])

  useEffect(() => {
    if (state !== 'running') return
    setElapsed(0)
    const t0 = Date.now()
    const id = window.setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 1000)
    return () => window.clearInterval(id)
  }, [state])

  useEffect(() => {
    setState('idle'); setResult(null); setScanId(null)
    if (pollRef.current) { window.clearInterval(pollRef.current); pollRef.current = null }
  }, [selected?.id])

  const poll = async (id: number) => {
    const resp = await fetch(`/api/agent-audit/scans/${id}`, { credentials: 'include' })
    if (!resp.ok) return
    const data: ScanResult = await resp.json()
    setResult(data)
    if (data.status === 'done') {
      setState('done')
      if (pollRef.current) { window.clearInterval(pollRef.current); pollRef.current = null }
    } else if (data.status === 'failed') {
      setState('error')
      if (pollRef.current) { window.clearInterval(pollRef.current); pollRef.current = null }
    }
  }

  const startScan = async () => {
    if (!selected) return
    setState('running'); setResult(null); setExpandedPath(null)
    const resp = await fetch('/api/agent-audit/scan', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_id: selected.id }),
    })
    const data = await resp.json().catch(() => null)
    if (!resp.ok || !data?.scan_id) { setState('error'); return }
    setScanId(data.scan_id)
    poll(data.scan_id)
    pollRef.current = window.setInterval(() => poll(data.scan_id), 5000)
  }

  const sinkRules = result?.sink_rules ?? ['rce', 'sqli', 'ssti', 'id']

  return (
    <div className="card flex h-full flex-col p-6">
      {/* 顶部：目标选择 + 操作按钮 */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold text-brand-text">Agent 审计</h2>
          <label className="text-xs text-brand-secondary">源代码目标:</label>
          <TargetPicker
            targets={targets}
            selectedId={selected?.id ?? null}
            disabled={state === 'running'}
            onSelect={(id) => select(id ? (targets.find(t => t.id === id) ?? null) : null)}
          />
        </div>
        {selected && state !== 'running' && (
          <button className="btn-primary" onClick={startScan}>
            {state === 'done' || state === 'error' ? '🔄 重新分析' : '🔍 开始 Agent 审计'}
          </button>
        )}
      </div>

      {/* 空状态 */}
      {!selected && (
        <div className="flex flex-1 items-center justify-center text-brand-secondary">
          请从上方选择一个源代码目标开始 Agent 审计
        </div>
      )}

      {/* 运行中：4 个 sink 进度 */}
      {state === 'running' && (
        <div className="flex flex-1 flex-col gap-4 overflow-auto">
          <div className="flex items-center gap-2 text-sm text-brand-secondary">
            <span className="h-2 w-2 animate-pulse rounded-full bg-brand-primary" />
            <span>正在分析 Agent 危险调用路径 · 已用时 {elapsed}s</span>
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {sinkRules.map(sink => {
              const ss = result?.sink_status?.[sink]
              const total = ss?.counts ? Object.values(ss.counts).reduce((a, b) => a + b, 0) : 0
              const success = ss?.counts?.success ?? 0
              const running = ss?.counts?.running ?? 0
              const queued = ss?.counts?.queued ?? 0
              return (
                <div key={sink} className="rounded-xl border border-brand-border bg-brand-bg2 p-4">
                  <div className={`mb-2 text-sm font-semibold ${SINK_COLOR[sink]}`}>{SINK_LABELS[sink]}</div>
                  {ss ? (
                    <div className="space-y-1 text-xs text-brand-secondary">
                      <div className="flex gap-3">
                        <span className="text-green-500 font-medium">✓ 已验证 {success}</span>
                        <span>{running > 0 ? `⚡ 运行中 ${running}` : ''}</span>
                        <span>{queued > 0 ? `⏳ 排队 ${queued}` : ''}</span>
                      </div>
                      <div className="h-1.5 w-full overflow-hidden rounded-full bg-brand-border">
                        <div className="h-full bg-brand-primary transition-all"
                          style={{ width: total > 0 ? `${Math.round((success / total) * 100)}%` : '5%' }} />
                      </div>
                    </div>
                  ) : (
                    <div className="text-xs text-brand-muted">等待启动…</div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* 错误 */}
      {state === 'error' && (
        <div className="flex flex-1 items-center justify-center text-brand-primary">
          {result?.error ?? '分析引擎暂不可用，请稍后重试'}
        </div>
      )}

      {/* 完成：结果展示 */}
      {state === 'done' && result && (
        <div className="flex flex-1 flex-col gap-4 overflow-hidden">
          {/* 汇总 KPI */}
          <div className="flex flex-wrap gap-4 rounded-xl bg-brand-bg2 px-6 py-4">
            <div className="text-center">
              <div className="text-3xl font-bold text-brand-primary">{result.verified_success ?? 0}</div>
              <div className="text-xs text-brand-muted">攻击路径已验证</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-brand-text">{result.total_executed ?? 0}</div>
              <div className="text-xs text-brand-muted">路径已执行</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-brand-text">
                {Object.values(result.paths_by_sink ?? {}).reduce((a, v) => a + v.total_paths, 0)}
              </div>
              <div className="text-xs text-brand-muted">静态路径总数</div>
            </div>
            <div className="ml-auto self-center text-xs text-brand-muted">
              项目: <span className="font-mono text-brand-text">{result.cuscuta_project}</span>
            </div>
          </div>

          {/* Sink 切换 tab */}
          <div className="flex gap-1 border-b border-brand-border">
            {sinkRules.map(sink => {
              const pathData = result.paths_by_sink?.[sink]
              const detailData = result.detail_by_sink?.[sink]
              const successCount = detailData?.paths?.filter(p => p.dynamic_success).length ?? 0
              return (
                <button
                  key={sink}
                  onClick={() => setActiveSink(sink)}
                  className={`px-3 py-2 text-xs font-medium transition-colors border-b-2 -mb-px ${
                    activeSink === sink
                      ? 'border-brand-primary text-brand-primary'
                      : 'border-transparent text-brand-secondary hover:text-brand-text'
                  }`}
                >
                  {sink.toUpperCase()}
                  {pathData && (
                    <span className="ml-1.5 text-brand-muted">
                      {successCount > 0
                        ? <span className="text-red-500 font-bold">{successCount} 攻击成功</span>
                        : `${pathData.total_paths} 路径`}
                    </span>
                  )}
                </button>
              )
            })}
          </div>

          {/* 路径列表 */}
          <div className="flex-1 overflow-auto">
            <PathList
              sink={activeSink}
              paths={result.paths_by_sink?.[activeSink]?.paths ?? []}
              details={result.detail_by_sink?.[activeSink]?.paths ?? []}
              expandedPath={expandedPath}
              onToggle={(key) => setExpandedPath(prev => prev === key ? null : key)}
            />
          </div>
        </div>
      )}
    </div>
  )
}

function PathList({ sink, paths, details, expandedPath, onToggle }: {
  sink: string
  paths: PathItem[]
  details: DetailPath[]
  expandedPath: string | null
  onToggle: (key: string) => void
}) {
  if (paths.length === 0) {
    return <div className="py-8 text-center text-sm text-brand-muted">该漏洞类型未发现风险路径</div>
  }

  // 建立 path→detail 映射
  const detailMap = new Map(details.map(d => [d.path, d]))

  return (
    <div className="space-y-2">
      {paths.map((p) => {
        const detail = detailMap.get(p.path)
        const isSuccess = detail?.dynamic_success === true
        const isExpanded = expandedPath === p.path_key
        return (
          <div key={p.path_key}
            className={`rounded-xl border ${isSuccess ? 'border-red-400 bg-red-50' : 'border-brand-border bg-brand-bg2'}`}>
            <button
              className="w-full px-4 py-3 text-left"
              onClick={() => onToggle(p.path_key)}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    {isSuccess && (
                      <span className="rounded-full bg-red-500 px-2 py-0.5 text-xs font-bold text-white shrink-0">
                        攻击成功
                      </span>
                    )}
                    {p.middles.length > 0 && (
                      <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs text-amber-700 shrink-0">
                        LLM 边界点 ×{p.middles.length}
                      </span>
                    )}
                    <span className="text-xs text-brand-muted shrink-0">
                      污点数 {p.taints}
                    </span>
                  </div>
                  <div className="mt-1.5 font-mono text-xs text-brand-text break-all leading-relaxed">
                    {p.path}
                  </div>
                </div>
                <span className="text-brand-muted text-sm shrink-0">{isExpanded ? '▲' : '▼'}</span>
              </div>
            </button>

            {isExpanded && (
              <div className="border-t border-brand-border px-4 pb-4 pt-3 space-y-3">
                {/* LLM 边界点 */}
                {p.middles.length > 0 && (
                  <div>
                    <div className="mb-1.5 text-xs font-semibold text-brand-secondary">LLM 边界点（外部输入进入 Agent 的方法）</div>
                    <div className="space-y-1">
                      {p.middles.map((m, i) => (
                        <div key={i} className="rounded-lg bg-amber-50 border border-amber-200 px-3 py-2 font-mono text-xs">
                          <span className="text-amber-700">{m.short_method}</span>
                          <span className="text-brand-muted ml-2">{m.filename}:{m.call_line}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 攻击详情（仅有 detail 时显示） */}
                {detail && detail.dynamic_success && (
                  <div>
                    <div className="mb-1.5 text-xs font-semibold text-red-600">攻击 Prompt（注入载荷）</div>
                    <pre className="overflow-x-auto rounded-lg bg-gray-900 p-3 text-xs text-green-400 whitespace-pre-wrap break-all">
                      {detail.prompt ?? '（无）'}
                    </pre>
                  </div>
                )}

                {detail?.chat_interaction && detail.chat_interaction.length > 0 && (
                  <div>
                    <div className="mb-1.5 text-xs font-semibold text-brand-secondary">攻击对话记录</div>
                    <div className="space-y-1.5 max-h-56 overflow-y-auto">
                      {detail.chat_interaction.map((msg, i) => (
                        <div key={i} className={`rounded px-3 py-2 text-xs ${
                          msg.role === 'user' ? 'bg-blue-50 text-blue-800' : 'bg-gray-50 text-gray-800'
                        }`}>
                          <span className="font-semibold mr-1">{msg.role}:</span>
                          <span className="whitespace-pre-wrap">{msg.content}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {detail && !detail.dynamic_success && (
                  <div className="text-xs text-brand-muted">
                    该路径已执行动态验证，暂未成功触发漏洞
                  </div>
                )}
                {!detail && (
                  <div className="text-xs text-brand-muted">
                    该路径尚未执行动态验证（仅静态发现）
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
