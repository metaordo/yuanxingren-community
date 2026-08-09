import React, { useEffect, useState } from 'react'

interface PriceRow {
  price_in_per_mtok: number
  price_out_per_mtok: number
  updated_at?: string
}

// 各模型单价(¥ / 百万 tokens),admin 维护,用于把 token 计数换算成报告成本。
export default function PriceManager() {
  const [known, setKnown] = useState<string[]>([])
  const [rows, setRows] = useState<Record<string, PriceRow>>({})
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [saving, setSaving] = useState(false)

  const load = async () => {
    try {
      const resp = await fetch('/api/admin/prices', { credentials: 'include' })
      if (!resp.ok) { setError('需要管理员权限'); return }
      const data = await resp.json()
      setKnown(data.known_models || [])
      const r: Record<string, PriceRow> = {}
      for (const m of data.known_models || [])
        r[m] = data.prices[m] || { price_in_per_mtok: 0, price_out_per_mtok: 0 }
      setRows(r)
    } catch (err: any) { setError(err.message) }
  }

  useEffect(() => { load() }, [])

  const setField = (model: string, field: keyof PriceRow, v: string) => {
    setRows(prev => ({ ...prev, [model]: { ...prev[model], [field]: parseFloat(v) || 0 } }))
  }

  const save = async () => {
    setSaving(true); setMsg(''); setError('')
    try {
      const prices = known.map(m => ({
        model_name: m,
        price_in_per_mtok: rows[m]?.price_in_per_mtok || 0,
        price_out_per_mtok: rows[m]?.price_out_per_mtok || 0,
      }))
      const resp = await fetch('/api/admin/prices', {
        method: 'PUT', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prices }),
      })
      if (resp.ok) { const d = await resp.json(); setMsg(`已保存 ${d.updated} 个模型单价`) }
      else setError('保存失败')
    } catch (err: any) { setError(err.message) } finally { setSaving(false) }
  }

  return (
    <div className="flex-1 overflow-y-auto p-5">
      {error && (
        <div className="mb-3 rounded-xl border border-brand-danger/20 bg-brand-dangerLight px-4 py-3 text-sm text-brand-danger">
          {error}
        </div>
      )}
      <p className="mb-3 text-xs text-brand-muted">
        单价单位:¥ / 百万 tokens。报告成本 = 输入 tok × 输入单价 + 输出 tok × 输出单价。未设单价的模型按 ¥0 计。
      </p>
      <div className="overflow-hidden rounded-xl border border-brand-border">
        <table className="w-full text-sm">
          <thead className="bg-brand-bg2 text-xs text-brand-secondary">
            <tr>
              <th className="px-4 py-2 text-left">模型</th>
              <th className="px-4 py-2 text-right">输入 ¥/1M</th>
              <th className="px-4 py-2 text-right">输出 ¥/1M</th>
            </tr>
          </thead>
          <tbody>
            {known.map(m => (
              <tr key={m} className="border-t border-brand-border">
                <td className="px-4 py-2 font-mono text-xs text-brand-text">{m}</td>
                <td className="px-4 py-2 text-right">
                  <input type="number" step="0.01" min="0"
                    value={rows[m]?.price_in_per_mtok ?? 0}
                    onChange={e => setField(m, 'price_in_per_mtok', e.target.value)}
                    className="input-field w-24 text-right" />
                </td>
                <td className="px-4 py-2 text-right">
                  <input type="number" step="0.01" min="0"
                    value={rows[m]?.price_out_per_mtok ?? 0}
                    onChange={e => setField(m, 'price_out_per_mtok', e.target.value)}
                    className="input-field w-24 text-right" />
                </td>
              </tr>
            ))}
            {known.length === 0 && !error && (
              <tr><td colSpan={3} className="py-12 text-center text-sm text-brand-muted">暂无可定价模型</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="mt-4 flex items-center gap-3">
        <button onClick={save} disabled={saving}
          className="rounded-lg bg-brand-primary px-4 py-2 text-sm font-medium text-white transition hover:opacity-90 disabled:opacity-50">
          {saving ? '保存中…' : '保存单价'}
        </button>
        {msg && <span className="text-xs text-brand-primary">{msg}</span>}
      </div>
    </div>
  )
}
