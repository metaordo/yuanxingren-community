import React from 'react'
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, act, waitFor } from '@testing-library/react'
import { TargetSelectionProvider, useTargetSelection, ACCEPT } from './targetSelection'
import { mockTargetsFetch, sampleTargets } from '../test/mocks'

function Probe({ scope }: { scope: 'scan' | 'multi_agent' | 'chat' }) {
  const { targets, selected } = useTargetSelection(scope)
  return (
    <div>
      <span data-testid={`${scope}-count`}>{targets.length}</span>
      <span data-testid={`${scope}-types`}>{targets.map(t => t.type).join(',')}</span>
      <span data-testid={`${scope}-selected`}>{selected ? selected.id : 'none'}</span>
    </div>
  )
}

beforeEach(() => { mockTargetsFetch() })
afterEach(() => { vi.restoreAllMocks() })

describe('TargetSelectionProvider', () => {
  test('scan scope only contains url/ip/domain/protocol', async () => {
    render(
      <TargetSelectionProvider>
        <Probe scope="scan" />
      </TargetSelectionProvider>
    )
    await waitFor(() => expect(screen.getByTestId('scan-count').textContent).not.toBe('0'))
    const types = screen.getByTestId('scan-types').textContent!.split(',')
    expect(types.every(t => ACCEPT.scan.includes(t))).toBe(true)
    expect(types).toContain('url')
    expect(types).toContain('ip')
  })

  test('multi_agent scope only contains source/binary/pcap', async () => {
    render(
      <TargetSelectionProvider>
        <Probe scope="multi_agent" />
      </TargetSelectionProvider>
    )
    await waitFor(() => expect(screen.getByTestId('multi_agent-count').textContent).not.toBe('0'))
    const types = screen.getByTestId('multi_agent-types').textContent!.split(',')
    expect(types.every(t => ACCEPT.multi_agent.includes(t))).toBe(true)
  })

  test('chat scope contains all sample types', async () => {
    render(
      <TargetSelectionProvider>
        <Probe scope="chat" />
      </TargetSelectionProvider>
    )
    await waitFor(() => expect(Number(screen.getByTestId('chat-count').textContent))
      .toBe(sampleTargets.length))
  })

  function Selector({ scope, target }: any) {
    const { select } = useTargetSelection(scope)
    React.useEffect(() => { select(target) }, [])
    return null
  }

  test('select() persists to localStorage with scope-specific key', async () => {
    render(
      <TargetSelectionProvider>
        <Selector scope="scan" target={sampleTargets[0]} />
        <Probe scope="scan" />
      </TargetSelectionProvider>
    )
    await waitFor(() => expect(localStorage.getItem('pa:sel:scan')).not.toBeNull())
    const stored = JSON.parse(localStorage.getItem('pa:sel:scan')!)
    expect(stored.id).toBe(sampleTargets[0].id)
    expect(localStorage.getItem('pa:sel:multi_agent')).toBeNull()
    expect(localStorage.getItem('pa:sel:chat')).toBeNull()
  })

  test('mount loads persisted selection from localStorage when target still exists', async () => {
    localStorage.setItem('pa:sel:scan', JSON.stringify(sampleTargets[0]))
    render(
      <TargetSelectionProvider>
        <Probe scope="scan" />
      </TargetSelectionProvider>
    )
    await waitFor(() => expect(screen.getByTestId('scan-selected').textContent)
      .toBe(String(sampleTargets[0].id)))
  })

  test('mount discards persisted selection when target no longer in /targets', async () => {
    localStorage.setItem('pa:sel:scan', JSON.stringify({
      id: 999, type: 'url', value: 'https://stale.example',
    }))
    render(
      <TargetSelectionProvider>
        <Probe scope="scan" />
      </TargetSelectionProvider>
    )
    await waitFor(() => expect(screen.getByTestId('scan-count').textContent).not.toBe('0'))
    expect(screen.getByTestId('scan-selected').textContent).toBe('none')
  })

  test('pa:target_deleted event clears matching selection only in affected scope', async () => {
    localStorage.setItem('pa:sel:scan', JSON.stringify(sampleTargets[0]))
    localStorage.setItem('pa:sel:chat', JSON.stringify(sampleTargets[2]))
    render(
      <TargetSelectionProvider>
        <Probe scope="scan" />
        <Probe scope="chat" />
      </TargetSelectionProvider>
    )
    await waitFor(() => expect(screen.getByTestId('scan-selected').textContent)
      .toBe(String(sampleTargets[0].id)))

    // delete the url target on server side + dispatch event
    mockTargetsFetch(sampleTargets.filter(t => t.id !== sampleTargets[0].id))
    await act(async () => {
      window.dispatchEvent(new CustomEvent('pa:target_deleted', {
        detail: { id: sampleTargets[0].id },
      }))
    })
    await waitFor(() => expect(screen.getByTestId('scan-selected').textContent).toBe('none'))
    // chat selection untouched (it was on a different target)
    expect(screen.getByTestId('chat-selected').textContent).toBe(String(sampleTargets[2].id))
  })

  test('selecting in scan does not affect multi_agent or chat selection', async () => {
    function MultiSelector() {
      const scan = useTargetSelection('scan')
      const ma = useTargetSelection('multi_agent')
      const ch = useTargetSelection('chat')
      React.useEffect(() => {
        scan.select(sampleTargets[0])
      }, [])
      return (
        <>
          <span data-testid="ma-sel">{ma.selected?.id ?? 'none'}</span>
          <span data-testid="ch-sel">{ch.selected?.id ?? 'none'}</span>
        </>
      )
    }
    render(
      <TargetSelectionProvider>
        <MultiSelector />
      </TargetSelectionProvider>
    )
    await waitFor(() => {})
    expect(screen.getByTestId('ma-sel').textContent).toBe('none')
    expect(screen.getByTestId('ch-sel').textContent).toBe('none')
  })
})
