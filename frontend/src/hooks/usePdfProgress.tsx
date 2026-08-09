import { useEffect, useRef, useState } from 'react'

/** Synthetic progress for the PDF render endpoint.
 *
 * The backend is a sync weasyprint call (~7s) with no real progress signal;
 * we fake one to make the wait feel shorter. Schedule is calibrated from
 * VPS bench: warm renders of typical multi-agent reports land at ~6.4s.
 *
 * Bench numbers and rationale live in
 * `docs/superpowers/specs/2026-05-27-pdf-progress-ux-design.md`.
 */
const PDF_PHASES: { until: number; pctEnd: number; label: string }[] = [
  { until: 600,  pctEnd: 15, label: '解析 markdown 与 codehilite' },
  { until: 3400, pctEnd: 55, label: '渲染中文字体' },
  { until: 5400, pctEnd: 85, label: '排版分页与代码高亮' },
  { until: 6400, pctEnd: 95, label: '编码并打包 PDF' },
]
const PDF_FREEZE_AFTER_MS = 8000
const PDF_BUDGET_MS = 6400

export interface PdfProgress {
  elapsedMs: number
  pct: number
  label: string
  etaMs: number | null
  frozen: boolean
}

function computePdfProgress(elapsedMs: number): Omit<PdfProgress, 'elapsedMs'> {
  if (elapsedMs >= PDF_FREEZE_AFTER_MS) {
    return { pct: 95, label: '仍在处理，请稍候', etaMs: null, frozen: true }
  }
  let prevPct = 0, prevUntil = 0
  for (const p of PDF_PHASES) {
    if (elapsedMs <= p.until) {
      const t = (elapsedMs - prevUntil) / (p.until - prevUntil)
      return {
        pct: prevPct + t * (p.pctEnd - prevPct),
        label: p.label,
        etaMs: Math.max(0, PDF_BUDGET_MS - elapsedMs),
        frozen: false,
      }
    }
    prevPct = p.pctEnd; prevUntil = p.until
  }
  const over = elapsedMs - PDF_BUDGET_MS
  const climb = 4.5 * (1 - Math.exp(-over / 1500))
  return { pct: 95 + climb, label: '编码并打包 PDF', etaMs: null, frozen: false }
}

export function usePdfProgress(active: boolean): PdfProgress {
  const [elapsedMs, setElapsedMs] = useState(0)
  const startRef = useRef<number>(0)
  useEffect(() => {
    if (!active) { setElapsedMs(0); return }
    startRef.current = performance.now()
    setElapsedMs(0)
    const id = window.setInterval(() => {
      setElapsedMs(performance.now() - startRef.current)
    }, 250)
    return () => window.clearInterval(id)
  }, [active])
  return { elapsedMs, ...computePdfProgress(elapsedMs) }
}
