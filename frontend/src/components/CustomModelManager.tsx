import React, { useEffect, useState } from 'react'

interface CustomModel {
  id: number
  name: string
  display: string
  provider: string
  base_url: string
  capabilities: string[]
}

interface TestResult {
  ok: boolean
  latency_ms: number
  reply_excerpt: string
  error: string | null
}

type Provider = 'openai_compat' | 'anthropic_proxy'

const PRESETS = [
  { label: '通义千问 (DashScope)', provider: 'openai_compat' as Provider, base_url: 'https://dashscope.aliyuncs.com/compatible-mode/v1', test_model: 'qwen-max' },
  { label: 'Moonshot Kimi', provider: 'openai_compat' as Provider, base_url: 'https://api.moonshot.cn/v1', test_model: 'moonshot-v1-8k' },
  { label: 'DeepSeek', provider: 'openai_compat' as Provider, base_url: 'https://api.deepseek.com/v1', test_model: 'deepseek-chat' },
  { label: '智谱 GLM', provider: 'openai_compat' as Provider, base_url: 'https://open.bigmodel.cn/api/paas/v4', test_model: 'glm-4' },
  { label: '本地 vLLM', provider: 'openai_compat' as Provider, base_url: 'http://localhost:8000/v1', test_model: 'qwen3-72b' },
  { label: '本地 Ollama', provider: 'openai_compat' as Provider, base_url: 'http://localhost:11434/v1', test_model: 'llama3' },
  { label: '其他 (自定义)', provider: 'openai_compat' as Provider, base_url: '', test_model: '' },
]

const PROVIDER_LABEL: Record<Provider, string> = { openai_compat: 'OpenAI 兼容', anthropic_proxy: 'Anthropic 兼容' }

export default function CustomModelManager() {
  const [models, setModels] = useState<CustomModel[]>([])
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ name: '', display: '', provider: 'openai_compat' as Provider, base_url: '', api_key: '', test_model_id: '', context_window: 32768, capabilities: 'coding,tool_use' })
  const [presetHint, setPresetHint] = useState('')
  const [test, setTest] = useState<TestResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')

  const load = async () => { try { const r = await fetch('/api/llm/custom', { credentials: 'include' }); if (r.ok) setModels(await r.json()) } catch (e: any) { setMsg('错误: ' + e.message) } }
  useEffect(() => { load() }, [])

  const applyPreset = (idx: number) => { const p = PRESETS[idx]; setForm({ ...form, provider: p.provider, base_url: p.base_url, test_model_id: p.test_model }); setPresetHint((p as any).hint || ''); setTest(null) }

  const runTest = async () => { setTest(null); setBusy(true); try { const r = await fetch('/api/llm/test-connection', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ base_url: form.base_url, api_key: form.api_key, test_model_id: form.test_model_id || form.name, provider: form.provider }) }); setTest(await r.json()) } finally { setBusy(false) } }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setMsg(''); setBusy(true)
    try {
      const r = await fetch('/api/llm/custom', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: form.name, display: form.display || form.name, provider: form.provider, base_url: form.base_url, api_key: form.api_key, context_window: form.context_window, capabilities: form.capabilities.split(',').map(s => s.trim()).filter(Boolean) }) })
      const data = await r.json()
      if (r.ok) { setMsg(`已添加 ${data.name}`); setCreating(false); setForm({ name: '', display: '', provider: 'openai_compat', base_url: '', api_key: '', test_model_id: '', context_window: 32768, capabilities: 'coding,tool_use' }); setTest(null); setPresetHint(''); load() }
      else setMsg(data.detail || '添加失败')
    } finally { setBusy(false) }
  }

  const remove = async (id: number, name: string) => { if (!confirm(`确认删除模型 ${name}？`)) return; await fetch(`/api/llm/custom/${id}`, { method: 'DELETE', credentials: 'include' }); load() }

  return (
    <div className="card p-6">
      <div className="mb-5 flex items-center justify-between">
        <div>
          <h3 className="text-base font-semibold text-brand-text">自定义模型</h3>
          <p className="mt-1 text-sm text-brand-secondary">注册第三方或本地 LLM 端点</p>
        </div>
        <button onClick={() => setCreating(!creating)} className={creating ? 'btn-ghost' : 'btn-primary'}>
          {creating ? '取消' : '+ 添加模型'}
        </button>
      </div>

      {creating && (
        <form onSubmit={submit} className="mb-5 space-y-3 rounded-xl border border-brand-border bg-brand-bg2 p-5">
          <div>
            <label className="mb-1.5 block text-sm font-medium text-brand-text">厂商预设</label>
            <select onChange={e => applyPreset(parseInt(e.target.value))} defaultValue="-1" className="input-field">
              <option value="-1" disabled>选择厂商...</option>
              {PRESETS.map((p, i) => <option key={i} value={i}>{p.label}</option>)}
            </select>
            {presetHint && <p className="mt-1.5 text-xs text-brand-muted">{presetHint}</p>}
          </div>

          <div>
            <label className="mb-1.5 block text-sm font-medium text-brand-text">协议</label>
            <div className="grid grid-cols-2 gap-2">
              {(['openai_compat', 'anthropic_proxy'] as Provider[]).map(p => (
                <button key={p} type="button" onClick={() => setForm({ ...form, provider: p })}
                  className={`rounded-xl border px-3 py-2.5 text-sm transition ${form.provider === p ? 'border-brand-primary bg-brand-primaryLight text-brand-primary font-medium' : 'border-brand-border text-brand-secondary hover:bg-brand-bg3'}`}>
                  {PROVIDER_LABEL[p]}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="模型名（唯一）" required className="input-field" />
            <input value={form.display} onChange={e => setForm({ ...form, display: e.target.value })} placeholder="显示名" className="input-field" />
          </div>
          <input value={form.base_url} onChange={e => setForm({ ...form, base_url: e.target.value })} placeholder="Base URL" required className="input-field" />
          <input type="password" value={form.api_key} onChange={e => setForm({ ...form, api_key: e.target.value })} placeholder="API Key" className="input-field" />
          <input value={form.test_model_id} onChange={e => setForm({ ...form, test_model_id: e.target.value })} placeholder="远端 model id（测试用）" className="input-field" />
          <div className="grid grid-cols-2 gap-3">
            <input type="number" value={form.context_window} onChange={e => setForm({ ...form, context_window: parseInt(e.target.value) })} className="input-field" />
            <input value={form.capabilities} onChange={e => setForm({ ...form, capabilities: e.target.value })} placeholder="能力标签" className="input-field" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <button type="button" onClick={runTest} disabled={busy || !form.base_url} className="btn-secondary">
              {busy ? '测试中...' : '测试连接'}
            </button>
            <button type="submit" disabled={busy || !form.name || !form.base_url} className="btn-primary">保存模型</button>
          </div>
          {test && (
            <div className={`rounded-xl p-3 text-sm ${test.ok ? 'border border-brand-success/20 bg-brand-successLight text-brand-success' : 'border border-brand-danger/20 bg-brand-dangerLight text-brand-danger'}`}>
              {test.ok ? '✓ 连接成功' : '✗ 连接失败'} · {test.latency_ms}ms
              {test.ok && <div className="mt-1 font-mono text-xs">{test.reply_excerpt}</div>}
              {test.error && <div className="mt-1 break-all font-mono text-xs">{test.error}</div>}
            </div>
          )}
        </form>
      )}

      {msg && <p className="mb-4 text-sm text-brand-secondary">{msg}</p>}

      <div className="space-y-2">
        {models.map(m => (
          <div key={m.id} className="flex items-center gap-3 rounded-xl border border-brand-border bg-white p-4">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-brand-text">{m.display}</span>
                <span className="badge badge-info">{PROVIDER_LABEL[m.provider as Provider] || m.provider}</span>
              </div>
              <div className="mt-1 truncate font-mono text-xs text-brand-muted">{m.base_url}</div>
            </div>
            <button onClick={() => remove(m.id, m.name)} className="rounded-lg border border-brand-danger/20 bg-brand-dangerLight px-3 py-1.5 text-xs text-brand-danger hover:bg-red-100">
              删除
            </button>
          </div>
        ))}
        {models.length === 0 && <p className="py-6 text-center text-sm text-brand-muted">尚未注册自定义模型</p>}
      </div>
    </div>
  )
}
