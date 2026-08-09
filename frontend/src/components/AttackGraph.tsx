import React, { useMemo } from 'react'

interface Evidence { kind: string; summary: string; confidence: number }
/**
 * Findings reach this component from two distinct buses:
 *   - engine mode (chat.py / orchestrator) → typed `Finding` with `id` + `evidence: Evidence[]`
 *   - multi_agent mode (workflow.py verifier) → dict with no `id`, `evidence: string`,
 *     and `category` may be missing (uses `role` instead).
 * We accept both shapes loosely and normalize inside the component so the
 * graph degrades gracefully instead of crashing.
 */
interface Finding {
  id?: string
  title: string
  severity: string
  category?: string
  role?: string
  evidence?: Evidence[] | string
  cwe?: string | null
  cve?: string | null
}
interface Props { findings: Finding[]; targetLabel?: string }

const SEVERITY_COLOR: Record<string, string> = { critical: '#dc2626', high: '#e53834', medium: '#d97706', low: '#059669', info: '#2563eb' }
const SEVERITY_LABEL: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' }

export default function AttackGraph({ findings, targetLabel = '目标' }: Props) {
  const layout = useMemo(() => computeLayout(findings), [findings])

  if (findings.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center p-8 text-center">
        <svg className="mb-4 h-16 w-16 text-brand-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0 0 20.25 18V6A2.25 2.25 0 0 0 18 3.75H6A2.25 2.25 0 0 0 3.75 6v12A2.25 2.25 0 0 0 6 20.25Z" />
        </svg>
        <h3 className="text-lg font-semibold text-brand-text">暂无发现</h3>
        <p className="mt-2 max-w-sm text-sm text-brand-secondary">发起安全测试后，证据图将展示目标、发现与证据之间的关系</p>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b border-brand-border px-5 py-4">
        <div>
          <h3 className="text-base font-semibold text-brand-text">证据图</h3>
          <p className="mt-0.5 text-sm text-brand-secondary">{findings.length} 个节点 · 目标居中</p>
        </div>
        <div className="flex items-center gap-3">
          {Object.entries(SEVERITY_COLOR).map(([sev, color]) => (
            <span key={sev} className="flex items-center gap-1.5 text-xs text-brand-secondary">
              <span style={{ background: color }} className="inline-block h-2.5 w-2.5 rounded-full" />
              {SEVERITY_LABEL[sev]}
            </span>
          ))}
        </div>
      </div>

      <div className="flex-1 p-4">
        <svg viewBox="0 0 600 500" className="h-full w-full">
          <defs>
            <radialGradient id="grad-target"><stop offset="0%" stopColor="#e53834" stopOpacity="0.9" /><stop offset="100%" stopColor="#e53834" stopOpacity="0.5" /></radialGradient>
            <filter id="shadow"><feDropShadow dx="0" dy="2" stdDeviation="3" floodOpacity="0.15" /></filter>
          </defs>

          {layout.findings.map(node => (
            <line key={`e-${node.id}`} x1={300} y1={250} x2={node.x} y2={node.y}
              stroke={SEVERITY_COLOR[node.finding.severity] || '#9ca3af'} strokeWidth={1.5} strokeOpacity={0.4} />
          ))}

          {layout.findings.flatMap(node =>
            node.evidence.map((ev, i) => (
              <g key={`ev-${node.id}-${i}`}>
                <line x1={node.x} y1={node.y} x2={ev.x} y2={ev.y} stroke="#d1d5db" strokeWidth={1} strokeDasharray="4,3" />
                <circle cx={ev.x} cy={ev.y} r={4} fill="#f3f4f6" stroke="#9ca3af" strokeWidth={1} />
              </g>
            ))
          )}

          {layout.findings.map(node => (
            <g key={node.id} filter="url(#shadow)">
              <circle cx={node.x} cy={node.y} r={22} fill="white" stroke={SEVERITY_COLOR[node.finding.severity] || '#9ca3af'} strokeWidth={2.5} />
              <circle cx={node.x} cy={node.y} r={8} fill={SEVERITY_COLOR[node.finding.severity] || '#9ca3af'} />
              <text x={node.x} y={node.y + 38} textAnchor="middle" fill="#121419" style={{ fontSize: 11, fontFamily: 'Inter, sans-serif', fontWeight: 500 }}>
                {truncate(node.finding.title, 20)}
              </text>
              <text x={node.x} y={node.y + 52} textAnchor="middle" fill="#9ca3af" style={{ fontSize: 9, fontFamily: 'Inter, sans-serif' }}>
                {node.finding.category || node.finding.role || ''}
              </text>
            </g>
          ))}

          <g filter="url(#shadow)">
            <circle cx={300} cy={250} r={36} fill="url(#grad-target)" />
            <circle cx={300} cy={250} r={5} fill="white" />
            <text x={300} y={300} textAnchor="middle" fill="#121419" style={{ fontSize: 12, fontWeight: 600, fontFamily: 'Inter, sans-serif' }}>
              {truncate(targetLabel, 28)}
            </text>
          </g>
        </svg>
      </div>
    </div>
  )
}

function computeLayout(findings: Finding[]) {
  const center = { x: 300, y: 250 }
  const radius = 150
  const placed = findings.map((f, i) => {
    const angle = (2 * Math.PI * i) / findings.length - Math.PI / 2
    const x = center.x + radius * Math.cos(angle)
    const y = center.y + radius * Math.sin(angle)
    // Evidence may arrive as Evidence[] (engine mode) or a raw string (multi_agent
    // verifier output). Strings have no .map — coerce to a single pseudo-evidence.
    const evRaw = f.evidence
    const evList: Evidence[] = Array.isArray(evRaw)
      ? evRaw
      : (typeof evRaw === 'string' && evRaw.trim())
        ? [{ kind: 'snippet', summary: evRaw, confidence: 0.5 }]
        : []
    const evidence = evList.slice(0, 3).map((ev, j) => {
      const evAngle = angle + (j - 1) * 0.25
      return { ...ev, x: center.x + (radius + 70) * Math.cos(evAngle), y: center.y + (radius + 70) * Math.sin(evAngle) }
    })
    // Findings without an explicit `id` (multi_agent path) need a stable key.
    const id = f.id || `f-${i}-${(f.title || '').slice(0, 16)}`
    return { id, x, y, finding: f, evidence }
  })
  return { findings: placed }
}

function truncate(s: string, n: number) { return s.length > n ? s.slice(0, n - 1) + '…' : s }
