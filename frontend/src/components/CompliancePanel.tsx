import { useEffect, useRef, useState } from 'react'
import { useTargetSelection } from '../api/targetSelection'
import { usePdfProgress } from '../hooks/usePdfProgress'
import { TargetPicker } from './TargetPicker'

type ScanState = 'idle' | 'consent' | 'running' | 'done' | 'error'

interface Match {
  your_file: string; lines: string; match_type: string
  source_project: string; source_version: string; source_file: string
  similarity: number; license: string
}
interface Result {
  status: string; progress: number; stage?: string
  reuse_ratio: number; self_ratio: number; verdict: string
  by_project: { project: string; version: string; ratio: number; file_count: number }[]
  matches: Match[]; skipped: string[]; error?: string
}

const VERDICT_COLOR: Record<string, string> = {
  '高度自研': 'bg-emerald-500', '以自研为主': 'bg-teal-500',
  '混合': 'bg-amber-500', '以复用为主': 'bg-orange-500', '高度复用': 'bg-brand-primary',
}

export default function CompliancePanel() {
  const { targets, selected, select } = useTargetSelection('compliance')
  const [state, setState] = useState<ScanState>('idle')
  const [result, setResult] = useState<Result | null>(null)
  const [generatingPdf, setGeneratingPdf] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const pdfProgress = usePdfProgress(generatingPdf)
  const pollRef = useRef<number | null>(null)

  useEffect(() => () => { if (pollRef.current) window.clearInterval(pollRef.current) }, [])

  // Tick an elapsed-seconds counter while a scan runs, so the user always sees
  // movement even between the (slower) backend progress updates.
  useEffect(() => {
    if (state !== 'running') return
    setElapsed(0)
    const t0 = Date.now()
    const id = window.setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 1000)
    return () => window.clearInterval(id)
  }, [state])

  // Switching to a different target resets the panel for a fresh run, so a
  // finished scan never blocks starting the next one.
  useEffect(() => {
    setState('idle')
    setResult(null)
    if (pollRef.current) { window.clearInterval(pollRef.current); pollRef.current = null }
  }, [selected?.id])

  const beginConsent = () => setState('consent')

  const startScan = async () => {
    if (!selected) return
    setState('running'); setResult(null)
    const resp = await fetch('/api/compliance/scan', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_id: selected.id }),
    })
    const data = await resp.json().catch(() => null)
    if (!resp.ok || !data?.scan_id) { setState('error'); return }
    poll(data.scan_id)  // immediate first poll so a stage shows right away
    pollRef.current = window.setInterval(() => poll(data.scan_id), 2000)
  }

  const poll = async (id: number) => {
    const resp = await fetch(`/api/compliance/scan/${id}`, { credentials: 'include' })
    const data: Result = await resp.json()
    setResult(data)
    if (data.status === 'done') { setState('done'); stop() }
    else if (data.status === 'failed') { setState('error'); stop() }
  }
  const stop = () => { if (pollRef.current) { window.clearInterval(pollRef.current); pollRef.current = null } }

  const exportPdf = async () => {
    if (!result) return
    setGeneratingPdf(true)
    try {
      const md = buildComplianceMarkdown(selected?.value ?? '', result)
      const resp = await fetch('/api/reports/render-pdf', {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: md, mode: 'compliance',
                               target_label: selected ? `#${selected.id} ${selected.value}` : '' }),
      })
      const blob = await resp.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = 'compliance.pdf'; a.click()
      URL.revokeObjectURL(url)
    } finally { setGeneratingPdf(false) }
  }

  return (
    <div className="card flex h-full flex-col p-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold text-brand-text">合规检查</h2>
          <label className="text-xs text-brand-secondary">源代码目标:</label>
          <TargetPicker
            targets={targets}
            selectedId={selected?.id ?? null}
            disabled={state === 'running'}
            onSelect={(id) => select(id ? (targets.find(t => t.id === id) ?? null) : null)}
          />
        </div>
        {selected && state !== 'running' && state !== 'consent' && (
          <button className="btn-primary" onClick={beginConsent}>
            {state === 'done' || state === 'error' ? '🔄 重新检查' : '🔍 开始合规检查'}
          </button>)}
      </div>

      {!selected && (
        <div className="flex flex-1 items-center justify-center text-brand-secondary">
          请从上方选择一个源代码目标开始合规检查
        </div>)}

      {state === 'consent' && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="card max-w-md p-6">
            <h3 className="mb-3 text-base font-semibold text-brand-text">隐私提示</h3>
            <p className="mb-5 text-sm text-brand-secondary">
              本次检查将提取您代码的<b>结构指纹</b>(非原始代码)发送至<b>元星刃开源比对引擎</b>
              进行公开开源库匹配。指纹不可逆向还原为源码。是否继续?
            </p>
            <div className="flex justify-end gap-3">
              <button className="btn-ghost" onClick={() => setState('idle')}>取消</button>
              <button className="btn-primary" onClick={startScan}>同意并继续</button>
            </div>
          </div>
        </div>)}

      {state === 'running' && (
        <div className="flex flex-1 flex-col items-center justify-center gap-4 text-brand-secondary">
          <div className="flex items-center gap-2 text-sm">
            <span className="h-2 w-2 animate-pulse rounded-full bg-brand-primary" />
            <span>{result?.stage ?? '正在准备…'}</span>
          </div>
          <div className="h-2 w-72 max-w-[80%] overflow-hidden rounded-full bg-brand-bg2">
            <div className="h-full bg-brand-primary transition-all duration-500"
                 style={{ width: `${result?.progress ?? 5}%` }} />
          </div>
          <div className="text-xs text-brand-muted">
            {result?.progress ?? 5}% · 已用时 {elapsed}s
          </div>
        </div>)}

      {state === 'error' && (
        <div className="flex flex-1 items-center justify-center text-brand-primary">
          {result?.error ?? '比对引擎暂不可用,请稍后重试'}
        </div>)}

      {state === 'done' && result && (
        <div className="flex flex-1 flex-col gap-6 overflow-hidden">
          <div className="flex items-center justify-around rounded-xl bg-brand-bg2 p-6">
            <div className="text-center">
              <div className="text-4xl font-bold text-brand-text">{Math.round(result.self_ratio * 100)}%</div>
              <div className="text-xs text-brand-muted">自研率</div>
            </div>
            <div className="text-center">
              <div className="text-4xl font-bold text-brand-primary">{Math.round(result.reuse_ratio * 100)}%</div>
              <div className="text-xs text-brand-muted">复用率</div>
            </div>
            <span className={`rounded-full px-4 py-1.5 text-sm font-medium text-white ${VERDICT_COLOR[result.verdict] ?? 'bg-gray-500'}`}>
              {result.verdict}
            </span>
          </div>
          <p className="text-xs text-brand-muted">⚠ 基于公开开源库比对,未匹配 ≠ 一定原创</p>

          <div className="flex flex-wrap gap-3">
            {result.by_project.map((p) => (
              <div key={p.project} className="rounded-lg border border-brand-border p-4">
                <div className="font-medium text-brand-text">{p.project} <span className="text-xs text-brand-muted">{p.version}</span></div>
                <div className="mt-1 text-sm text-brand-primary">{Math.round(p.ratio * 100)}%</div>
                <div className="text-xs text-brand-muted">{p.file_count} 个文件</div>
              </div>))}
          </div>

          <div className="flex-1 overflow-auto">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-brand-muted">
                <th className="p-2">你的文件</th><th>行范围</th><th>类型</th>
                <th>来源项目 / 文件</th><th>相似</th></tr></thead>
              <tbody>
                {result.matches.map((m, i) => (
                  <tr key={i} className="border-t border-brand-border">
                    <td className="p-2 font-mono text-xs">{m.your_file}</td>
                    <td>{m.lines}</td>
                    <td>{m.match_type === 'file' ? '整文件' : '片段'}</td>
                    <td>{m.source_project}/{m.source_file}</td>
                    <td>{m.match_type === 'file' ? '全文' : `${m.similarity}%`}</td>
                  </tr>))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-xs text-brand-muted">⊘ 已跳过 {result.skipped.length} 个文件(二进制/生成文件)</span>
            <button className="btn-primary" onClick={exportPdf} disabled={generatingPdf}>
              {generatingPdf ? `正在生成 PDF… ${Math.round(pdfProgress.pct)}%` : '导出 PDF'}
            </button>
          </div>
        </div>)}
    </div>
  )
}

function buildComplianceMarkdown(targetValue: string, r: Result): string {
  const lines: string[] = []
  lines.push(`# 开源合规溯源报告\n`)
  lines.push(`**目标**:${targetValue}\n`)
  lines.push(`**自研率**:${Math.round(r.self_ratio * 100)}%  **复用率**:${Math.round(r.reuse_ratio * 100)}%  **结论**:${r.verdict}\n`)
  lines.push(`> 基于公开开源库比对,未匹配 ≠ 一定原创\n`)
  lines.push(`## 按开源项目聚合\n`)
  for (const p of r.by_project)
    lines.push(`- **${p.project}** ${p.version} — ${Math.round(p.ratio * 100)}%(${p.file_count} 个文件)`)
  lines.push(`\n## 逐文件溯源\n`)
  lines.push(`| 你的文件 | 行范围 | 类型 | 来源 | 相似 |`)
  lines.push(`|---|---|---|---|---|`)
  for (const m of r.matches)
    lines.push(`| ${m.your_file} | ${m.lines} | ${m.match_type === 'file' ? '整文件' : '片段'} | ${m.source_project}/${m.source_file} | ${m.match_type === 'file' ? '全文' : m.similarity + '%'} |`)
  lines.push(`\n已跳过 ${r.skipped.length} 个文件(二进制/生成文件)`)
  return lines.join('\n')
}
