import React, { useEffect, useState } from 'react'
import ReportViewer from './ReportViewer'

interface ReportItem {
  type: 'multi_agent' | 'compliance' | 'zap'
  id: number
  owner_id: number
  owner_username: string | null
  target: string
  status: string
  stats: any
  created_at: string
  finished_at: string | null
}

interface UserOpt { id: number; username: string }

const TYPE_LABEL: Record<string, string> = {
  multi_agent: '多 Agent',
  compliance: '合规',
  zap: 'X-Scan',
}

function statsSummary(item: ReportItem): string {
  const s = item.stats || {}
  if (item.type === 'multi_agent') {
    const cost = s.cost_cny ?? 0
    const costStr = cost > 0 ? ` · ¥${cost.toFixed(2)}` : ''
    return `${s.findings ?? 0} findings · ${s.agents ?? 0} agents · ${(s.tokens_in ?? 0) + (s.tokens_out ?? 0)} tok${costStr}`
  }
  if (item.type === 'compliance')
    return `复用率 ${Math.round((s.reuse_ratio ?? 0) * 100)}% · ${s.verdict ?? '—'}`
  if (item.type === 'zap') {
    const risks = Object.entries(s.risk_summary || {}).map(([k, v]) => `${k}:${v}`).join(' ')
    return `${s.num_alerts ?? 0} 告警${risks ? ' · ' + risks : ''}`
  }
  return ''
}

export default function ReportBrowser() {
  const [items, setItems] = useState<ReportItem[]>([])
  const [users, setUsers] = useState<UserOpt[]>([])
  const [typeFilter, setTypeFilter] = useState('')
  const [userFilter, setUserFilter] = useState('')
  const [selected, setSelected] = useState<ReportItem | null>(null)
  const [detail, setDetail] = useState<any>(null)
  const [error, setError] = useState('')

  const load = async () => {
    const params = new URLSearchParams()
    if (typeFilter) params.set('type', typeFilter)
    if (userFilter) params.set('user_id', userFilter)
    try {
      const resp = await fetch('/api/admin/reports?' + params.toString(), { credentials: 'include' })
      if (resp.ok) setItems(await resp.json())
      else setError('需要管理员权限')
    } catch (e: any) { setError(e.message) }
  }

  useEffect(() => {
    fetch('/auth/users', { credentials: 'include' })
      .then(r => r.ok ? r.json() : [])
      .then((us: any[]) => setUsers(us.map(u => ({ id: u.id, username: u.username }))))
      .catch(() => {})
  }, [])

  useEffect(() => { load() }, [typeFilter, userFilter])

  const openReport = async (item: ReportItem) => {
    setSelected(item)
    setDetail(null)
    try {
      const resp = await fetch(`/api/admin/reports/${item.type}/${item.id}`, { credentials: 'include' })
      if (resp.ok) setDetail(await resp.json())
    } catch { /* noop */ }
  }

  return (
    <div className="flex h-full min-h-0">
      {/* list */}
      <div className="flex w-full flex-col sm:w-1/2 sm:border-r border-brand-border">
        <div className="flex gap-2 border-b border-brand-border px-4 py-3">
          <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
            className="rounded-lg border border-brand-border bg-brand-bg2 px-2 py-1 text-xs">
            <option value="">全部类型</option>
            <option value="multi_agent">多 Agent</option>
            <option value="compliance">合规</option>
            <option value="zap">X-Scan</option>
          </select>
          <select value={userFilter} onChange={e => setUserFilter(e.target.value)}
            className="rounded-lg border border-brand-border bg-brand-bg2 px-2 py-1 text-xs">
            <option value="">全部用户</option>
            {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select>
        </div>
        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          {error && <p className="text-sm text-brand-danger">{error}</p>}
          {items.length === 0 && !error && <p className="text-sm text-brand-muted">暂无报告</p>}
          {items.map(item => (
            <button key={`${item.type}-${item.id}`} onClick={() => openReport(item)}
              className={`w-full rounded-xl border p-3 text-left transition ${
                selected?.type === item.type && selected?.id === item.id
                  ? 'border-brand-primary bg-brand-primaryLight'
                  : 'border-brand-border bg-white hover:bg-brand-bg2'}`}>
              <div className="flex items-center justify-between">
                <span className="badge badge-info">{TYPE_LABEL[item.type]}</span>
                <span className="text-xs text-brand-muted">{item.owner_username || `#${item.owner_id}`}</span>
              </div>
              <div className="mt-1 truncate text-sm font-medium text-brand-text">{item.target}</div>
              <div className="mt-0.5 text-xs text-brand-secondary">{statsSummary(item)}</div>
              <div className="mt-0.5 text-xs text-brand-muted">{new Date(item.created_at).toLocaleString()}</div>
            </button>
          ))}
        </div>
      </div>
      {/* detail */}
      <div className="hidden flex-1 overflow-y-auto p-5 sm:block">
        {!selected && <p className="text-sm text-brand-muted">选择左侧报告查看详情</p>}
        {selected && !detail && <p className="text-sm text-brand-muted">加载中…</p>}
        {selected && detail && (
          <div>
            <div className="mb-4 border-b border-brand-border pb-3">
              <div className="text-sm font-semibold text-brand-text">{TYPE_LABEL[selected.type]} · {selected.target}</div>
              <div className="mt-1 text-xs text-brand-muted">归属：{selected.owner_username || `#${selected.owner_id}`} · {new Date(selected.created_at).toLocaleString()}</div>
            </div>
            <ReportViewer report={detail} />
          </div>
        )}
      </div>
    </div>
  )
}
