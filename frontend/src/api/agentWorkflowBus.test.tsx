import React from 'react'
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, act, waitFor } from '@testing-library/react'
import { usePipelineStates } from './agentWorkflowBus'

afterEach(() => { vi.restoreAllMocks() })

function Probe() {
  const pipes = usePipelineStates()
  return (
    <div>
      <span data-testid="chat-find">{pipes.chat.findings.length}</span>
      <span data-testid="scan-find">{pipes.scan.findings.length}</span>
      <span data-testid="ma-find">{pipes.multi_agent.findings.length}</span>

      <span data-testid="chat-prog">{Object.keys(pipes.chat.progress).join(',')}</span>
      <span data-testid="scan-prog">{Object.keys(pipes.scan.progress).join(',')}</span>
      <span data-testid="ma-prog">{Object.keys(pipes.multi_agent.progress).join(',')}</span>

      <span data-testid="chat-rep">{pipes.chat.report?.content ?? 'none'}</span>
      <span data-testid="scan-rep">{pipes.scan.report?.content ?? 'none'}</span>
      <span data-testid="ma-rep">{pipes.multi_agent.report?.content ?? 'none'}</span>
    </div>
  )
}

const fire = (type: string, detail: any) => {
  act(() => {
    window.dispatchEvent(new CustomEvent(type, { detail }))
  })
}

describe('usePipelineStates — per-source routing', () => {
  test('pa:findings with source routes only to that source bucket', async () => {
    render(<Probe />)
    fire('pa:findings', { source: 'multi_agent', findings: [{ id: 'a' }, { id: 'b' }] })
    await waitFor(() => expect(screen.getByTestId('ma-find').textContent).toBe('2'))
    expect(screen.getByTestId('chat-find').textContent).toBe('0')
    expect(screen.getByTestId('scan-find').textContent).toBe('0')
  })

  test('pa:findings legacy array detail defaults to chat (backward compat)', async () => {
    render(<Probe />)
    fire('pa:findings', [{ id: 'x' }])
    await waitFor(() => expect(screen.getByTestId('chat-find').textContent).toBe('1'))
    expect(screen.getByTestId('scan-find').textContent).toBe('0')
    expect(screen.getByTestId('ma-find').textContent).toBe('0')
  })

  test('pa:workflow_progress with source updates only that bucket', async () => {
    render(<Probe />)
    fire('pa:workflow_progress', { source: 'multi_agent', stepId: 'supervisor', status: 'running' })
    fire('pa:workflow_progress', { source: 'scan', stepId: 'spider', status: 'running' })
    await waitFor(() => {
      expect(screen.getByTestId('ma-prog').textContent).toBe('supervisor')
      expect(screen.getByTestId('scan-prog').textContent).toBe('spider')
    })
    expect(screen.getByTestId('chat-prog').textContent).toBe('')
  })

  test('pa:workflow_progress reset clears only the specified source', async () => {
    render(<Probe />)
    fire('pa:workflow_progress', { source: 'multi_agent', stepId: 'workers', status: 'running' })
    fire('pa:workflow_progress', { source: 'scan', stepId: 'spider', status: 'running' })
    await waitFor(() => expect(screen.getByTestId('scan-prog').textContent).toBe('spider'))
    // Reset multi_agent only — scan should be untouched.
    fire('pa:workflow_progress', { source: 'multi_agent', reset: true })
    await waitFor(() => expect(screen.getByTestId('ma-prog').textContent).toBe(''))
    expect(screen.getByTestId('scan-prog').textContent).toBe('spider')
  })

  test('pa:report_available with source routes only to that bucket', async () => {
    render(<Probe />)
    fire('pa:report_available', { source: 'scan', content: 'scan-report-md', mode: 'engine' })
    await waitFor(() => expect(screen.getByTestId('scan-rep').textContent).toBe('scan-report-md'))
    expect(screen.getByTestId('chat-rep').textContent).toBe('none')
    expect(screen.getByTestId('ma-rep').textContent).toBe('none')
  })

  test('legacy pa:report_available without source defaults to chat', async () => {
    render(<Probe />)
    fire('pa:report_available', { content: 'legacy-content', mode: 'direct' })
    await waitFor(() => expect(screen.getByTestId('chat-rep').textContent).toBe('legacy-content'))
    expect(screen.getByTestId('scan-rep').textContent).toBe('none')
    expect(screen.getByTestId('ma-rep').textContent).toBe('none')
  })

  test('three concurrent runs each accumulate progress independently', async () => {
    render(<Probe />)
    fire('pa:workflow_progress', { source: 'chat', stepId: 'planner', status: 'running' })
    fire('pa:workflow_progress', { source: 'scan', stepId: 'spider', status: 'running' })
    fire('pa:workflow_progress', { source: 'multi_agent', stepId: 'supervisor', status: 'running' })
    await waitFor(() => {
      expect(screen.getByTestId('chat-prog').textContent).toBe('planner')
      expect(screen.getByTestId('scan-prog').textContent).toBe('spider')
      expect(screen.getByTestId('ma-prog').textContent).toBe('supervisor')
    })
  })
})
