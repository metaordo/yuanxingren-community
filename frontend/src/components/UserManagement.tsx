import React, { useEffect, useState } from 'react'

interface User {
  id: number
  username: string
  role: 'admin' | 'operator' | 'viewer'
  is_active: boolean
  must_change_password: boolean
}

const ROLES = ['admin', 'operator', 'viewer'] as const
const ROLE_LABEL: Record<string, string> = { admin: '管理员', operator: '操作员', viewer: '观察者' }

export default function UserManagement() {
  const [users, setUsers] = useState<User[]>([])
  const [creating, setCreating] = useState(false)
  const [msg, setMsg] = useState('')
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'operator' as const })

  const load = async () => {
    try {
      const resp = await fetch('/auth/users', { credentials: 'include' })
      if (resp.ok) setUsers(await resp.json())
      else setMsg('需要管理员权限')
    } catch (err: any) { setMsg(err.message) }
  }

  useEffect(() => { load() }, [])

  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    setMsg('')
    try {
      const resp = await fetch('/auth/users', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newUser),
      })
      const data = await resp.json()
      if (!resp.ok) { setMsg(data.detail || '创建失败') }
      else {
        setMsg(`已创建: ${data.username}`)
        setNewUser({ username: '', password: '', role: 'operator' })
        setCreating(false)
        load()
      }
    } catch (err: any) { setMsg(err.message) }
  }

  const update = async (id: number, patch: any) => {
    const resp = await fetch(`/auth/users/${id}`, {
      method: 'PATCH', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    })
    if (resp.ok) load()
    else setMsg('更新失败')
  }

  const remove = async (id: number, name: string) => {
    if (!confirm(`确认彻底删除用户 "${name}"？\n\n此操作不可恢复，将一并物理删除该用户的目标、上传文件、扫描记录等全部数据。`)) return
    await fetch(`/auth/users/${id}`, { method: 'DELETE', credentials: 'include' })
    load()
  }

  return (
    <div className="card p-6">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold text-brand-text">用户管理</h3>
          <p className="mt-1 text-sm text-brand-secondary">管理系统账户与权限</p>
        </div>
        <button onClick={() => setCreating(!creating)} className={creating ? 'btn-ghost' : 'btn-primary'}>
          {creating ? '取消' : '+ 添加用户'}
        </button>
      </div>

      {creating && (
        <form onSubmit={create} className="mb-5 space-y-3 rounded-xl border border-brand-border bg-brand-bg2 p-4">
          <input value={newUser.username} onChange={e => setNewUser({ ...newUser, username: e.target.value })}
            placeholder="用户名（≥3 字符）" required minLength={3} className="input-field" />
          <input type="password" value={newUser.password} onChange={e => setNewUser({ ...newUser, password: e.target.value })}
            placeholder="密码（8+ 字符，含大小写+数字+符号）" required className="input-field" />
          <select value={newUser.role} onChange={e => setNewUser({ ...newUser, role: e.target.value as any })} className="input-field">
            {ROLES.map(r => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
          </select>
          <button type="submit" className="btn-primary w-full">创建用户</button>
        </form>
      )}

      {msg && <p className="mb-4 text-sm text-brand-secondary">{msg}</p>}

      <div className="space-y-2">
        {users.map(u => (
          <div key={u.id} className="flex items-center gap-3 rounded-xl border border-brand-border bg-white p-4">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-brand-bg3 text-sm font-semibold text-brand-secondary">
              {u.username[0].toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium text-brand-text">{u.username}</div>
              <div className="mt-0.5 flex items-center gap-2">
                <select value={u.role} onChange={e => update(u.id, { role: e.target.value })}
                  className="rounded-lg border border-brand-border bg-brand-bg2 px-2 py-1 text-xs text-brand-secondary">
                  {ROLES.map(r => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
                </select>
                {!u.is_active && <span className="badge badge-info">已禁用</span>}
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {u.is_active ? (
                <button onClick={() => { if (confirm(`禁用用户 "${u.username}"？该账号将无法登录，可随时重新启用。`)) update(u.id, { is_active: false }) }}
                  className="rounded-lg border border-brand-border bg-brand-bg2 px-3 py-1.5 text-xs text-brand-secondary hover:bg-brand-bg3">
                  禁用
                </button>
              ) : (
                <button onClick={() => update(u.id, { is_active: true })}
                  className="rounded-lg border border-brand-success/20 bg-brand-successLight px-3 py-1.5 text-xs text-brand-success hover:bg-green-100">
                  启用
                </button>
              )}
              <button onClick={() => remove(u.id, u.username)}
                className="rounded-lg border border-brand-danger/20 bg-brand-dangerLight px-3 py-1.5 text-xs text-brand-danger hover:bg-red-100">
                删除
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
