import React, { useEffect, useState } from 'react'

interface ModelInfo {
  name: string
  display: string
  provider: string
}

const TASKS = [
  { key: 'planning', label: '规划', desc: '任务分解与策略制定' },
  { key: 'codegen', label: '代码生成', desc: 'PoC 合成与漏洞利用' },
  { key: 'triage', label: '研判', desc: '快速分类与优先级排序' },
]

export default function ModelPicker() {
  const [models, setModels] = useState<ModelInfo[]>([])
  const [routes, setRoutes] = useState<Record<string, string>>({
    planning: 'claude-opus-4-7',
    codegen: 'claude-sonnet-4-6',
    triage: 'claude-haiku-4-5-20251001',
  })
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  useEffect(() => {
    fetch('/api/llm/models', { credentials: 'include' })
      .then(r => r.ok ? r.json() : { models: [] })
      .then(d => setModels(d.models || []))
      .catch(() => setModels([]))
    fetch('/api/llm/routes', { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (d && d.routes) {
          setRoutes(prev => ({ ...prev, ...d.routes }))
        }
      })
      .catch(() => {})
  }, [])

  const save = async () => {
    setMsg(null)
    try {
      const resp = await fetch('/api/llm/routes', {
        method: 'PUT',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ routes }),
      })
      setMsg(resp.ok
        ? { text: '路由已保存', ok: true }
        : { text: '保存失败', ok: false })
    } catch (e: any) {
      setMsg({ text: e.message, ok: false })
    }
  }

  return (
    <div className="card p-6">
      <div className="mb-5">
        <h3 className="text-base font-semibold text-brand-text">模型路由</h3>
        <p className="mt-1 text-sm text-brand-secondary">为不同任务类型分配 LLM 模型（共 {models.length} 个可用）</p>
      </div>

      <div className="space-y-4">
        {TASKS.map(task => (
          <div key={task.key}>
            <label className="mb-1.5 block text-sm font-medium text-brand-text">{task.label}</label>
            <p className="mb-2 text-xs text-brand-muted">{task.desc}</p>
            <select
              value={routes[task.key]}
              onChange={e => setRoutes({ ...routes, [task.key]: e.target.value })}
              className="input-field"
            >
              {models.length === 0 && (
                <option value={routes[task.key]}>{routes[task.key]}</option>
              )}
              {models.map(m => (
                <option key={m.name} value={m.name}>{m.display}</option>
              ))}
            </select>
          </div>
        ))}
      </div>

      {msg && (
        <div className={`mt-4 rounded-xl px-4 py-3 text-sm ${
          msg.ok
            ? 'border border-brand-success/20 bg-brand-successLight text-brand-success'
            : 'border border-brand-danger/20 bg-brand-dangerLight text-brand-danger'
        }`}>
          {msg.ok ? '✓' : '✗'} {msg.text}
        </div>
      )}

      <button onClick={save} className="btn-secondary mt-5 w-full">
        应用路由
      </button>
    </div>
  )
}
