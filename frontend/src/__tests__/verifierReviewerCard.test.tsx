import React from 'react'
import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AgentColumn } from '../components/MultiAgentDashboard'

// Minimal AgentRunState fixture helpers
function makeRun(overrides: Record<string, unknown> = {}) {
  return {
    run_id: 1,
    role: 'code-auditor',
    status: 'done' as const,
    findings: [],
    ...overrides,
  }
}

describe('AgentColumn — verifier-reviewer special visual', () => {
  test('regular worker card has no gray border class', () => {
    const { container } = render(
      <AgentColumn run={makeRun({ role: 'code-auditor', status: 'done' })} />,
    )
    const card = container.firstElementChild as HTMLElement
    expect(card.className).not.toContain('border-l-gray-400')
    expect(card.className).not.toContain('bg-gray-50')
  })

  test('verifier-reviewer card has gray left border + bg-gray-50', () => {
    const { container } = render(
      <AgentColumn run={makeRun({ role: 'verifier-reviewer', status: 'running' })} />,
    )
    const card = container.firstElementChild as HTMLElement
    expect(card.className).toContain('border-l-gray-400')
    expect(card.className).toContain('bg-gray-50')
  })

  test('verifier-reviewer role label is prefixed with 🔍', () => {
    render(
      <AgentColumn run={makeRun({ role: 'verifier-reviewer', status: 'running' })} />,
    )
    const label = screen.getByText(/🔍.*verifier-reviewer/)
    expect(label).toBeInTheDocument()
  })

  test('regular worker role label has no 🔍 prefix', () => {
    render(
      <AgentColumn run={makeRun({ role: 'xss-analyst', status: 'running' })} />,
    )
    expect(screen.queryByText(/🔍/)).not.toBeInTheDocument()
    expect(screen.getByText('xss-analyst')).toBeInTheDocument()
  })

  test('verifier-reviewer with findings shows "复查 N 条"', () => {
    const findings = [{ title: 'F1' }, { title: 'F2' }, { title: 'F3' }]
    render(
      <AgentColumn
        run={makeRun({ role: 'verifier-reviewer', status: 'done', findings })}
      />,
    )
    expect(screen.getByText(/复查 3 条/)).toBeInTheDocument()
  })

  test('regular worker with findings does NOT show "复查 N 条"', () => {
    const findings = [{ title: 'F1' }]
    render(
      <AgentColumn
        run={makeRun({ role: 'dep-analyst', status: 'done', findings })}
      />,
    )
    expect(screen.queryByText(/复查/)).not.toBeInTheDocument()
  })

  test('verifier-reviewer with no findings does not show "复查 0 条"', () => {
    render(
      <AgentColumn
        run={makeRun({ role: 'verifier-reviewer', status: 'running', findings: [] })}
      />,
    )
    expect(screen.queryByText(/复查/)).not.toBeInTheDocument()
  })
})
