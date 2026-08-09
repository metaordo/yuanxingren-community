import { useEffect, useState } from 'react'
import type { Mode } from './appState'

export type Source = 'chat' | 'scan' | 'multi_agent'

export interface ReportPayload { content: string; mode: Mode }

export type StepStatus = 'pending' | 'running' | 'done'
export type ProgressMap = Record<string, StepStatus>

export interface PipelineState {
  findings: any[]
  progress: ProgressMap
  report: ReportPayload | null
}

const EMPTY_PIPELINE: PipelineState = {
  findings: [],
  progress: {},
  report: null,
}

/** Read the `source` field on a CustomEvent detail. Detail variants:
 *   - new format: { source: Source, ...payload }
 *   - legacy array (pa:findings): defaults to 'chat'
 *   - legacy object missing source: defaults to 'chat'
 * Backward compatibility keeps ChatPanel unchanged. */
export function readSource(detail: any): Source {
  const s = detail && typeof detail === 'object' && !Array.isArray(detail)
    ? detail.source
    : undefined
  return s === 'scan' || s === 'multi_agent' ? s : 'chat'
}

/** Subscribe to all three global buses (pa:findings / pa:workflow_progress /
 *  pa:report_available), partition events by `source`, and return three
 *  per-source PipelineStates. Mounted once at Dashboard root so a long-running
 *  multi-agent task survives nav switches while scan / chat run independently.
 */
export function usePipelineStates(): Record<Source, PipelineState> {
  const [byChat, setChat] = useState<PipelineState>(EMPTY_PIPELINE)
  const [byScan, setScan] = useState<PipelineState>(EMPTY_PIPELINE)
  const [byMa, setMa] = useState<PipelineState>(EMPTY_PIPELINE)

  useEffect(() => {
    const setterFor = (src: Source): (mut: (s: PipelineState) => PipelineState) => void => {
      if (src === 'scan') return (mut) => setScan(mut)
      if (src === 'multi_agent') return (mut) => setMa(mut)
      return (mut) => setChat(mut)
    }

    const onFindings = (e: Event) => {
      const detail = (e as CustomEvent).detail
      const src = readSource(detail)
      const arr: any[] | undefined = Array.isArray(detail)
        ? detail
        : (detail && Array.isArray(detail.findings) ? detail.findings : undefined)
      if (arr === undefined) return
      setterFor(src)(prev => ({ ...prev, findings: arr }))
    }

    const onProgress = (e: Event) => {
      const detail = (e as CustomEvent).detail || {}
      const src = readSource(detail)
      if (detail.reset) {
        setterFor(src)(() => EMPTY_PIPELINE)
        return
      }
      if (!detail.stepId) return
      setterFor(src)(prev => ({
        ...prev,
        progress: { ...prev.progress, [detail.stepId]: detail.status || 'done' },
      }))
    }

    const onReport = (e: Event) => {
      const detail = (e as CustomEvent).detail
      if (!detail || typeof detail.content !== 'string' || !detail.content.trim()) return
      const src = readSource(detail)
      setterFor(src)(prev => ({
        ...prev,
        report: { content: detail.content, mode: detail.mode || 'direct' },
      }))
    }

    window.addEventListener('pa:findings', onFindings as EventListener)
    window.addEventListener('pa:workflow_progress', onProgress as EventListener)
    window.addEventListener('pa:report_available', onReport as EventListener)
    return () => {
      window.removeEventListener('pa:findings', onFindings as EventListener)
      window.removeEventListener('pa:workflow_progress', onProgress as EventListener)
      window.removeEventListener('pa:report_available', onReport as EventListener)
    }
  }, [])

  return { chat: byChat, scan: byScan, multi_agent: byMa }
}
