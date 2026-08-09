import React, { useEffect, useState } from 'react'

interface AuthScope {
  hosts: string[]
  cidrs: string[]
  note: string | null
}

export default function AuthScopeManager() {
  const [scope, setScope] = useState<AuthScope>({ hosts: [], cidrs: [], note: null })
  const [hostInput, setHostInput] = useState('')
  const [cidrInput, setCidrInput] = useState('')
  const [note, setNote] = useState('')
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  const load = async () => {
    setLoading(true)
    try {
      const resp = await fetch('/targets/auth-scope', { credentials: 'include' })
      if (resp.ok) {
        const data = await resp.json()
        setScope({
          hosts: data.hosts || [],
          cidrs: data.cidrs || [],
          note: data.note || null,
        })
        setNote(data.note || '')
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const save = async (next: AuthScope) => {
    setBusy(true)
    setMsg(null)
    try {
      const resp = await fetch('/targets/auth-scope', {
        method: 'PUT',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hosts: next.hosts,
          cidrs: next.cidrs,
          note: next.note || null,
        }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        setMsg({ text: err.detail || '保存失败', ok: false })
      } else {
        setScope(next)
        setMsg({ text: '授权范围已更新', ok: true })
      }
    } catch (e: any) {
      setMsg({ text: e.message, ok: false })
    } finally {
      setBusy(false)
    }
  }

  const addHost = () => {
    const v = hostInput.trim()
    if (!v) return
    if (scope.hosts.includes(v)) {
      setMsg({ text: '该主机已在授权范围内', ok: false })
      return
    }
    save({ ...scope, hosts: [...scope.hosts, v], note })
    setHostInput('')
  }

  const addCidr = () => {
    const v = cidrInput.trim()
    if (!v) return
    if (scope.cidrs.includes(v)) {
      setMsg({ text: '该 CIDR 已在授权范围内', ok: false })
      return
    }
    if (!/^[\d.:a-fA-F]+(\/\d{1,3})?$/.test(v)) {
      setMsg({ text: 'CIDR 格式无效，示例：192.168.0.0/16', ok: false })
      return
    }
    save({ ...scope, cidrs: [...scope.cidrs, v], note })
    setCidrInput('')
  }

  const removeHost = (v: string) => {
    save({ ...scope, hosts: scope.hosts.filter(h => h !== v), note })
  }

  const removeCidr = (v: string) => {
    save({ ...scope, cidrs: scope.cidrs.filter(c => c !== v), note })
  }

  const saveNote = () => {
    save({ ...scope, note })
  }

  const QUICK_PRESETS = [
    {
      label: '本机回环',
      hosts: ['localhost', '127.0.0.1'],
      cidrs: ['127.0.0.0/8'],
    },
    {
      label: '私有网段',
      hosts: [],
      cidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
    },
    {
      label: '本服务器',
      hosts: [],
      cidrs: [],
    },
  ]

  const applyPreset = (preset: typeof QUICK_PRESETS[number]) => {
    const newHosts = Array.from(new Set([...scope.hosts, ...preset.hosts]))
    const newCidrs = Array.from(new Set([...scope.cidrs, ...preset.cidrs]))
    save({ ...scope, hosts: newHosts, cidrs: newCidrs, note })
  }

  if (loading) {
    return (
      <div className="card p-6">
        <div className="text-sm text-brand-muted">加载授权范围...</div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="card p-6">
        <div className="mb-5">
          <h3 className="text-base font-semibold text-brand-text">授权范围管理</h3>
          <p className="mt-1 text-sm text-brand-secondary">
            创建目标时，目标地址必须落在已授权的主机或 CIDR 范围内。这是防止误扫到非授权目标的安全护栏。
          </p>
        </div>

        {/* Quick presets */}
        <div className="mb-5">
          <div className="mb-2 text-xs font-medium text-brand-secondary">快速预设</div>
          <div className="flex flex-wrap gap-2">
            {QUICK_PRESETS.map(p => (
              <button
                key={p.label}
                onClick={() => applyPreset(p)}
                disabled={busy}
                className="rounded-lg border border-brand-border bg-brand-bg2 px-3 py-1.5 text-xs text-brand-text transition hover:border-brand-primary hover:text-brand-primary disabled:opacity-60"
              >
                + {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Hosts */}
        <div className="mb-5">
          <label className="mb-2 block text-sm font-medium text-brand-text">
            授权主机 / 域名 / IP
          </label>
          <div className="mb-2 flex gap-2">
            <input
              value={hostInput}
              onChange={e => setHostInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addHost() } }}
              placeholder="例如 example.com 或 192.168.1.10"
              className="input-field flex-1"
              disabled={busy}
            />
            <button
              type="button"
              onClick={addHost}
              disabled={busy || !hostInput.trim()}
              className="btn-secondary shrink-0"
            >
              添加
            </button>
          </div>
          {scope.hosts.length === 0 ? (
            <div className="rounded-lg border border-dashed border-brand-border bg-brand-bg2 px-3 py-2.5 text-xs text-brand-muted">
              暂无授权主机
            </div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {scope.hosts.map(h => (
                <span
                  key={h}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-brand-bg3 px-2.5 py-1.5 text-xs text-brand-text"
                >
                  <svg className="h-3 w-3 text-brand-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 0 1 7.843 4.582M12 3a8.997 8.997 0 0 0-7.843 4.582m15.686 0A11.953 11.953 0 0 1 12 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0 1 21 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0 1 12 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 0 1 3 12c0-1.605.42-3.113 1.157-4.418" />
                  </svg>
                  {h}
                  <button
                    onClick={() => removeHost(h)}
                    disabled={busy}
                    className="ml-0.5 rounded-full p-0.5 text-brand-muted hover:bg-brand-border hover:text-brand-danger disabled:opacity-50"
                    title="移除"
                  >
                    <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
                    </svg>
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>

        {/* CIDRs */}
        <div className="mb-5">
          <label className="mb-2 block text-sm font-medium text-brand-text">
            授权 CIDR 网段
          </label>
          <div className="mb-2 flex gap-2">
            <input
              value={cidrInput}
              onChange={e => setCidrInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addCidr() } }}
              placeholder="例如 192.168.0.0/16 或 10.0.0.1/32"
              className="input-field flex-1"
              disabled={busy}
            />
            <button
              type="button"
              onClick={addCidr}
              disabled={busy || !cidrInput.trim()}
              className="btn-secondary shrink-0"
            >
              添加
            </button>
          </div>
          {scope.cidrs.length === 0 ? (
            <div className="rounded-lg border border-dashed border-brand-border bg-brand-bg2 px-3 py-2.5 text-xs text-brand-muted">
              暂无授权网段
            </div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {scope.cidrs.map(c => (
                <span
                  key={c}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-brand-bg3 px-2.5 py-1.5 text-xs font-mono text-brand-text"
                >
                  <svg className="h-3 w-3 text-brand-secondary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 6.75h12M8.25 12h12m-12 5.25h12M3.75 6.75h.007v.008H3.75V6.75Zm.375 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0ZM3.75 12h.007v.008H3.75V12Zm.375 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0ZM3.75 17.25h.007v.008H3.75v-.008Zm.375 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Z" />
                  </svg>
                  {c}
                  <button
                    onClick={() => removeCidr(c)}
                    disabled={busy}
                    className="ml-0.5 rounded-full p-0.5 text-brand-muted hover:bg-brand-border hover:text-brand-danger disabled:opacity-50"
                    title="移除"
                  >
                    <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
                    </svg>
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Note */}
        <div className="mb-4">
          <label className="mb-2 block text-sm font-medium text-brand-text">
            备注（可选）
          </label>
          <div className="flex gap-2">
            <input
              value={note}
              onChange={e => setNote(e.target.value)}
              onBlur={() => { if (note !== (scope.note || '')) saveNote() }}
              placeholder="例如：客户授权书编号、有效期"
              className="input-field flex-1"
              disabled={busy}
            />
          </div>
        </div>

        {msg && (
          <div
            className={`rounded-xl px-4 py-3 text-sm ${
              msg.ok
                ? 'border border-brand-success/20 bg-brand-successLight text-brand-success'
                : 'border border-brand-danger/20 bg-brand-dangerLight text-brand-danger'
            }`}
          >
            {msg.ok ? '✓' : '✗'} {msg.text}
          </div>
        )}
      </div>

      <div className="card p-6">
        <h4 className="mb-2 text-sm font-semibold text-brand-text">说明</h4>
        <ul className="space-y-2 text-xs text-brand-secondary">
          <li>· <strong className="text-brand-text">主机</strong> 接受完整的域名（example.com）、IP 地址（192.168.1.10），或单一 host:port 的简称。</li>
          <li>· <strong className="text-brand-text">CIDR</strong> 用于批量授权整个网段，例如内网 192.168.0.0/16，或仅单台主机 192.168.1.10/32。</li>
          <li>· 创建目标时后端会强制校验目标地址是否落在以上范围内。如果不在，会返回 <code className="rounded bg-brand-bg3 px-1 py-0.5 font-mono">out of authorized scope</code> 错误。</li>
          <li>· 添加 / 删除会立即保存。每位用户拥有独立的授权范围。</li>
        </ul>
      </div>
    </div>
  )
}
