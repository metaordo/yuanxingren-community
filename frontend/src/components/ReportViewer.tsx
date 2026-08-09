import React from 'react'
import ReactMarkdown from 'react-markdown'

// Shared markdown component styling (mirrors ChatPanel's report rendering).
const MD_COMPONENTS = {
  h1: ({ node, ...props }: any) => <h1 className="text-lg font-bold text-brand-text mt-4 mb-2 first:mt-0" {...props} />,
  h2: ({ node, ...props }: any) => <h2 className="text-base font-semibold text-brand-text mt-4 mb-2 first:mt-0" {...props} />,
  h3: ({ node, ...props }: any) => <h3 className="text-sm font-semibold text-brand-text mt-3 mb-1.5" {...props} />,
  p: ({ node, ...props }: any) => <p className="mb-3 last:mb-0 leading-relaxed" {...props} />,
  ul: ({ node, ...props }: any) => <ul className="mb-3 space-y-1.5 pl-5 list-disc marker:text-brand-muted" {...props} />,
  ol: ({ node, ...props }: any) => <ol className="mb-3 space-y-1.5 pl-5 list-decimal marker:text-brand-muted" {...props} />,
  li: ({ node, ...props }: any) => <li className="leading-relaxed" {...props} />,
  strong: ({ node, ...props }: any) => <strong className="font-semibold text-brand-text" {...props} />,
  code: ({ node, inline, ...props }: any) =>
    inline
      ? <code className="rounded bg-brand-bg3 px-1.5 py-0.5 text-xs font-mono text-brand-text" {...props} />
      : <code className="block rounded-lg bg-brand-bg3 p-3 text-xs font-mono text-brand-text overflow-x-auto" {...props} />,
  pre: ({ node, ...props }: any) => <pre className="mb-3 last:mb-0" {...props} />,
  table: ({ node, ...props }: any) => <table className="mb-3 w-full text-xs border-collapse" {...props} />,
  th: ({ node, ...props }: any) => <th className="border border-brand-border px-2 py-1 bg-brand-bg2 text-left" {...props} />,
  td: ({ node, ...props }: any) => <td className="border border-brand-border px-2 py-1" {...props} />,
}

const RISK_BADGE: Record<string, string> = {
  High: 'badge-high',
  Medium: 'badge-medium',
  Low: 'badge-low',
  Informational: 'badge-info',
}

interface ReportPayload {
  type: 'multi_agent' | 'compliance' | 'zap'
  [k: string]: any
}

export default function ReportViewer({ report }: { report: ReportPayload }) {
  if (report.type === 'multi_agent') {
    return (
      <div className="text-sm text-brand-secondary">
        {report.total_cost_cny > 0 && (
          <div className="mb-3 text-xs text-brand-secondary">
            合计成本 <span className="font-semibold text-brand-primary">¥{report.total_cost_cny.toFixed(2)}</span>
          </div>
        )}
        {report.runs?.length > 0 && (
          <div className="mb-4 flex flex-wrap gap-2">
            {report.runs.map((r: any, i: number) => (
              <span key={i} className="rounded-lg border border-brand-border bg-brand-bg2 px-2 py-1 text-xs">
                {r.role} · {r.status} · {r.findings} findings · {r.tokens_in + r.tokens_out} tok{r.cost_cny > 0 ? ` · ¥${r.cost_cny.toFixed(2)}` : ''}
              </span>
            ))}
          </div>
        )}
        <ReactMarkdown components={MD_COMPONENTS}>{report.markdown || '（无报告内容）'}</ReactMarkdown>
      </div>
    )
  }

  if (report.type === 'zap') {
    const alerts: any[] = report.alerts || []
    return (
      <div className="text-sm text-brand-secondary">
        <div className="mb-3 flex flex-wrap gap-2">
          {Object.entries(report.risk_summary || {}).map(([risk, n]) => (
            <span key={risk} className={`badge ${RISK_BADGE[risk] || 'badge-info'}`}>{risk}: {n as number}</span>
          ))}
          <span className="text-xs text-brand-muted">共 {report.num_alerts} 个告警</span>
        </div>
        <div className="space-y-2">
          {alerts.map((a, i) => (
            <div key={i} className="rounded-lg border border-brand-border bg-white p-3">
              <div className="flex items-center gap-2">
                <span className={`badge ${RISK_BADGE[a.risk] || 'badge-info'}`}>{a.risk}</span>
                <span className="font-medium text-brand-text">{a.name}</span>
              </div>
              {a.url && <div className="mt-1 text-xs text-brand-muted break-all">{a.url}{a.param ? ` · ${a.param}` : ''}</div>}
              {a.description && <p className="mt-1.5 text-xs leading-relaxed">{a.description}</p>}
              {a.evidence && <code className="mt-1.5 block rounded bg-brand-bg3 p-2 text-xs font-mono break-all">{a.evidence}</code>}
            </div>
          ))}
        </div>
      </div>
    )
  }

  // compliance
  const result = report.result || {}
  const byProject: Record<string, any> = result.by_project || {}
  return (
    <div className="text-sm text-brand-secondary">
      <div className="mb-3 flex flex-wrap gap-2">
        <span className="badge badge-info">复用率 {Math.round((report.reuse_ratio || 0) * 100)}%</span>
        <span className="rounded-lg border border-brand-border bg-brand-bg2 px-2 py-1 text-xs">判定：{report.verdict || '—'}</span>
      </div>
      {Object.keys(byProject).length > 0 ? (
        <div className="space-y-1.5">
          {Object.entries(byProject).map(([proj, info]: [string, any]) => (
            <div key={proj} className="flex items-center justify-between rounded-lg border border-brand-border bg-white px-3 py-2">
              <span className="font-mono text-xs text-brand-text break-all">{proj}</span>
              <span className="text-xs text-brand-muted">
                {typeof info === 'object' ? `${Math.round((info.ratio || info.percent || 0) * (info.ratio <= 1 ? 100 : 1))}%` : String(info)}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-xs text-brand-muted">无溯源明细。</p>
      )}
    </div>
  )
}
