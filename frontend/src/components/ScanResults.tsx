import React from 'react'

/* ── Scan result shape from the unified scan API ── */
interface ScanResultData {
  hosts: Array<{
    ip: string
    ports: Array<{
      port: string
      protocol: string
      state: string
      service: string
    }>
  }>
  services: Array<{
    ip: string
    port: string
    service: string
    protocol: string
  }>
  nse_vulns: Array<{
    ip: string
    port: string
    script_id: string
    output: string
  }>
  cve_matches: Array<{
    cve_id: string
    cvss_score: number
    severity: string
    description: string
    description_zh: string
    matched_service: string
    matched_port: string
  }>
}

/* ── Severity colour helper ── */
function severityColor(s: string): string {
  switch (s) {
    case 'CRITICAL':
      return 'text-red-400'
    case 'HIGH':
      return 'text-orange-400'
    case 'MEDIUM':
      return 'text-yellow-400'
    default:
      return 'text-slate-400'
  }
}

/* ── Component ── */
export default function ScanResults({ result }: { result: ScanResultData }) {
  const hasCve = result.cve_matches && result.cve_matches.length > 0

  return (
    <div className="card flex flex-col p-4 sm:p-5">
      {/* ── Open ports table ── */}
      <section className="mb-5">
        <h3 className="mb-2 text-sm font-semibold text-brand-text">
          开放端口
          {result.services && (
            <span className="ml-2 text-xs font-normal text-brand-muted">
              ({result.services.length})
            </span>
          )}
        </h3>
        <div className="overflow-x-auto rounded-lg border border-brand-border">
          <table className="w-full text-xs text-brand-secondary">
            <thead>
              <tr className="border-b border-brand-border bg-brand-bg2 text-left">
                <th className="px-3 py-2 font-medium">IP</th>
                <th className="px-3 py-2 font-medium">端口</th>
                <th className="px-3 py-2 font-medium">协议</th>
                <th className="px-3 py-2 font-medium">服务</th>
              </tr>
            </thead>
            <tbody>
              {(result.services ?? []).length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-3 py-6 text-center text-brand-muted">
                    未发现开放端口
                  </td>
                </tr>
              ) : (
                (result.services ?? []).map((s, i) => (
                  <tr key={i} className="border-b border-brand-border/50 last:border-b-0 hover:bg-brand-bg2/50">
                    <td className="px-3 py-1.5 font-mono">{s.ip}</td>
                    <td className="px-3 py-1.5 font-mono">{s.port}</td>
                    <td className="px-3 py-1.5">{s.protocol}</td>
                    <td className="px-3 py-1.5 text-brand-text">{s.service}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* ── NSE vulns ── */}
      {result.nse_vulns && result.nse_vulns.length > 0 && (
        <section className="mb-5">
          <h3 className="mb-2 text-sm font-semibold text-brand-text">
            NSE 脚本结果
            <span className="ml-2 text-xs font-normal text-brand-muted">
              ({result.nse_vulns.length})
            </span>
          </h3>
          <div className="space-y-2">
            {result.nse_vulns.slice(0, 20).map((v, i) => (
              <div key={i} className="rounded-lg border border-brand-border p-3 text-xs">
                <div className="mb-1 font-medium text-brand-text">
                  {v.script_id}
                  <span className="ml-2 text-brand-muted">
                    {v.ip}:{v.port}
                  </span>
                </div>
                <p className="whitespace-pre-wrap text-brand-secondary">
                  {v.output}
                </p>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── CVE matches ── */}
      {hasCve && (
        <section>
          <h3 className="mb-2 text-sm font-semibold text-brand-text">
            关联 CVE
            <span className="ml-2 text-xs font-normal text-brand-muted">
              ({result.cve_matches.length})
            </span>
          </h3>
          <div className="space-y-2">
            {result.cve_matches.slice(0, 50).map((cve, i) => (
              <div key={i} className="card p-3 text-xs">
                <div className="mb-1 flex items-center gap-2">
                  <span className="font-mono font-medium text-brand-text">
                    {cve.cve_id}
                  </span>
                  <span className={`font-semibold ${severityColor(cve.severity)}`}>
                    {cve.severity} {cve.cvss_score.toFixed(1)}
                  </span>
                  <span className="text-brand-muted">
                    · {cve.matched_service}:{cve.matched_port}
                  </span>
                </div>
                <p className="leading-relaxed text-brand-secondary">
                  {cve.description_zh || cve.description}
                </p>
              </div>
            ))}
          </div>
          {result.cve_matches.length > 50 && (
            <p className="mt-2 text-center text-xs text-brand-muted">
              仅显示前 50 条 CVE 结果
            </p>
          )}
        </section>
      )}

      {/* ── Empty state ── */}
      {!hasCve && (!result.nse_vulns || result.nse_vulns.length === 0) && (
        <p className="py-4 text-center text-sm text-brand-muted">
          未发现关联威胁信息
        </p>
      )}
    </div>
  )
}
