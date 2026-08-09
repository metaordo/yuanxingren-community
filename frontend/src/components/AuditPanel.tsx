import React, { useEffect, useState } from 'react'
import ReportBrowser from './ReportBrowser'
import PriceManager from './PriceManager'

interface AuditEntry {
  id: number
  kind: string
  actor_id: number | null
  actor_username: string | null
  object_kind: string | null
  object_id: string | null
  ip: string | null
  detail: any
  created_at: string
}

const KIND_LABELS: Record<string, string> = {
  login_success: '登录成功',
  login_failure: '登录失败',
  logout: '退出',
  password_change: '改密',
  user_create: '创建用户',
  user_update: '修改用户',
  user_deactivate: '禁用用户',
  target_create: '创建目标',
  target_access: '访问目标',
  scope_update: '修改范围',
  tool_invoke: '调用工具',
  poc_synthesize: '生成PoC',
  poc_sandbox_run: '沙箱执行',
  disclosure_draft: '披露草稿',
  model_register: '注册模型',
  route_update: '更新路由',
  analysis_complete: '多 Agent 分析',
  compliance_scan: '合规检查',
  zap_scan: 'X-Scan 扫描',
}

function isSecuritySignificant(kind: string): boolean {
  return ['login_failure', 'user_deactivate', 'user_update',
          'scope_update', 'poc_sandbox_run'].includes(kind)
}

export default function AuditPanel() {
  const [view, setView] = useState<'events' | 'reports' | 'prices'>('events')
  const [events, setEvents] = useState<AuditEntry[]>([])
  const [error, setError] = useState('')
  const [kindFilter, setKindFilter] = useState('')
  const [actorFilter, setActorFilter] = useState('')
  const [users, setUsers] = useState<{ id: number; username: string }[]>([])

  const load = async () => {
    const params = new URLSearchParams()
    if (kindFilter) params.set('kind', kindFilter)
    if (actorFilter) params.set('actor_id', actorFilter)
    const url = '/api/audit' + (params.toString() ? `?${params.toString()}` : '')
    try {
      const resp = await fetch(url, { credentials: 'include' })
      if (resp.ok) setEvents(await resp.json())
      else setError('需要管理员权限')
    } catch (err: any) {
      setError(err.message)
    }
  }

  useEffect(() => {
    fetch('/auth/users', { credentials: 'include' })
      .then(r => r.ok ? r.json() : [])
      .then((us: any[]) => setUsers(us.map(u => ({ id: u.id, username: u.username }))))
      .catch(() => {})
  }, [])

  useEffect(() => { load() }, [kindFilter, actorFilter])

  return (
    <div className="card flex h-full flex-col overflow-hidden">
      <div className="flex items-center justify-between border-b border-brand-border px-5 py-4">
        <div className="flex items-center gap-4">
          <h3 className="text-base font-semibold text-brand-text">审计</h3>
          <div className="flex gap-1">
            <button onClick={() => setView('events')}
              className={`rounded-lg px-3 py-1 text-sm transition ${view === 'events'
                ? 'bg-brand-primaryLight text-brand-primary font-medium'
                : 'text-brand-secondary hover:bg-brand-bg3'}`}>事件日志</button>
            <button onClick={() => setView('reports')}
              className={`rounded-lg px-3 py-1 text-sm transition ${view === 'reports'
                ? 'bg-brand-primaryLight text-brand-primary font-medium'
                : 'text-brand-secondary hover:bg-brand-bg3'}`}>用户报告</button>
            <button onClick={() => setView('prices')}
              className={`rounded-lg px-3 py-1 text-sm transition ${view === 'prices'
                ? 'bg-brand-primaryLight text-brand-primary font-medium'
                : 'text-brand-secondary hover:bg-brand-bg3'}`}>单价管理</button>
          </div>
        </div>
        {view === 'events' && (
          <div className="flex gap-2">
            <select value={actorFilter} onChange={e => setActorFilter(e.target.value)}
              className="input-field w-auto">
              <option value="">全部用户</option>
              {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
            </select>
            <select value={kindFilter} onChange={e => setKindFilter(e.target.value)}
              className="input-field w-auto">
              <option value="">全部事件</option>
              {Object.entries(KIND_LABELS).map(([k, v]) => (
                <option key={k} value={k}>{v}</option>
              ))}
            </select>
          </div>
        )}
      </div>

      {view === 'reports' ? (
        <div className="min-h-0 flex-1"><ReportBrowser /></div>
      ) : view === 'prices' ? (
        <div className="min-h-0 flex-1"><PriceManager /></div>
      ) : (
      <div className="flex-1 overflow-y-auto p-5">
        {error && (
          <div className="rounded-xl border border-brand-danger/20 bg-brand-dangerLight px-4 py-3 text-sm text-brand-danger">
            {error}
          </div>
        )}
        <div className="space-y-2">
          {events.map(e => (
            <div key={e.id}
                 className={`flex items-center gap-4 rounded-xl border px-4 py-3 text-sm ${
                   isSecuritySignificant(e.kind)
                     ? 'border-brand-danger/20 bg-brand-dangerLight'
                     : 'border-brand-border bg-white'
                 }`}>
              <div className="w-40 shrink-0 text-xs text-brand-muted">
                {new Date(e.created_at).toLocaleString('zh-CN', {
                  year: 'numeric', month: '2-digit', day: '2-digit',
                  hour: '2-digit', minute: '2-digit', second: '2-digit',
                  hour12: false,
                })}
              </div>
              <div className={`w-20 shrink-0 text-xs font-medium ${isSecuritySignificant(e.kind) ? 'text-brand-danger' : 'text-brand-primary'}`}>
                {KIND_LABELS[e.kind] || e.kind}
              </div>
              <div className="w-24 shrink-0 truncate text-xs text-brand-text">
                {e.actor_username || (e.actor_id != null ? users.find(u => u.id === e.actor_id)?.username : null) || '—'}
              </div>
              <div className="w-24 shrink-0 truncate text-xs text-brand-muted">
                {e.ip || '—'}
              </div>
              <div className="min-w-0 flex-1 truncate text-xs text-brand-muted">
                {e.object_kind ? `${e.object_kind}#${e.object_id}` : ''}
              </div>
            </div>
          ))}
          {events.length === 0 && !error && (
            <div className="py-12 text-center text-sm text-brand-muted">暂无审计事件</div>
          )}
        </div>
      </div>
      )}
    </div>
  )
}
