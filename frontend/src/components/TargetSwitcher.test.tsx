import React from 'react'
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { TargetSelectionProvider } from '../api/targetSelection'
import TargetSwitcher from './TargetSwitcher'
import { mockTargetsFetch, sampleTargets } from '../test/mocks'

beforeEach(() => { mockTargetsFetch() })
afterEach(() => { vi.restoreAllMocks() })

function renderWithProvider(scope: 'scan' | 'multi_agent' | 'chat') {
  return render(
    <TargetSelectionProvider>
      <TargetSwitcher scope={scope} />
    </TargetSelectionProvider>
  )
}

describe('TargetSwitcher', () => {
  test('dropdown lists only targets matching scope accept list', async () => {
    const user = userEvent.setup()
    renderWithProvider('scan')
    await waitFor(() => screen.getByRole('button'))
    await user.click(screen.getByRole('button'))
    // url + ip + domain present
    expect(screen.getByText(/sina\.com/)).toBeInTheDocument()
    expect(screen.getByText(/10\.0\.0\.1/)).toBeInTheDocument()
    expect(screen.getByText(/example\.com/)).toBeInTheDocument()
    // source / binary / pcap absent
    expect(screen.queryByText(/x\.zip/)).not.toBeInTheDocument()
    expect(screen.queryByText(/elf$/)).not.toBeInTheDocument()
  })

  test('clicking a row writes selection through the provider', async () => {
    const user = userEvent.setup()
    renderWithProvider('scan')
    await waitFor(() => screen.getByRole('button'))
    await user.click(screen.getByRole('button'))
    await user.click(screen.getByText(/sina\.com/))
    await waitFor(() => expect(screen.getByRole('button').textContent)
      .toMatch(/sina\.com/))
    expect(JSON.parse(localStorage.getItem('pa:sel:scan')!).value)
      .toBe('https://sina.com')
  })

  test('clicking 暂不选择 calls select(null)', async () => {
    const user = userEvent.setup()
    localStorage.setItem('pa:sel:scan', JSON.stringify(sampleTargets[0]))
    renderWithProvider('scan')
    await waitFor(() => expect(screen.getByRole('button').textContent).toMatch(/sina/))
    await user.click(screen.getByRole('button'))
    await user.click(screen.getByText('— 暂不选择 —'))
    await waitFor(() => expect(screen.getByRole('button').textContent)
      .toMatch(/选择目标/))
    expect(localStorage.getItem('pa:sel:scan')).toBeNull()
  })

  test('label shows currently-selected target', async () => {
    localStorage.setItem('pa:sel:multi_agent', JSON.stringify(sampleTargets[2]))
    renderWithProvider('multi_agent')
    await waitFor(() => expect(screen.getByRole('button').textContent).toMatch(/x\.zip/))
  })

  test('row delete button issues DELETE /targets/{id} and dispatches pa:target_deleted', async () => {
    const user = userEvent.setup()
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const fetchSpy = mockTargetsFetch()
    const dispatchSpy = vi.spyOn(window, 'dispatchEvent')
    renderWithProvider('scan')
    await waitFor(() => screen.getByRole('button'))
    await user.click(screen.getByRole('button'))
    // Each row has a delete button with aria-label "删除目标 #{id}"
    const delBtn = screen.getByLabelText(`删除目标 #${sampleTargets[0].id}`)
    await user.click(delBtn)
    expect(confirmSpy).toHaveBeenCalled()
    await waitFor(() => {
      expect(fetchSpy).toHaveBeenCalledWith(
        `/targets/${sampleTargets[0].id}`,
        expect.objectContaining({ method: 'DELETE' }),
      )
    })
    const dispatched = dispatchSpy.mock.calls
      .map(c => c[0])
      .filter((e: any) => e instanceof CustomEvent && e.type === 'pa:target_deleted')
    expect(dispatched.length).toBeGreaterThan(0)
  })

  test('delete is aborted when user cancels the confirm', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    const fetchSpy = mockTargetsFetch()
    renderWithProvider('scan')
    await waitFor(() => screen.getByRole('button'))
    await user.click(screen.getByRole('button'))
    const delBtn = screen.getByLabelText(`删除目标 #${sampleTargets[0].id}`)
    await user.click(delBtn)
    // fetch was called for initial /targets load but never for DELETE
    const deleteCalls = fetchSpy.mock.calls.filter(
      ([, opts]: any) => opts?.method === 'DELETE',
    )
    expect(deleteCalls).toHaveLength(0)
  })

  test('clicking the delete button does not toggle row selection', async () => {
    const user = userEvent.setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    mockTargetsFetch()
    renderWithProvider('scan')
    await waitFor(() => screen.getByRole('button'))
    await user.click(screen.getByRole('button'))
    const delBtn = screen.getByLabelText(`删除目标 #${sampleTargets[0].id}`)
    await user.click(delBtn)
    // The selection should NOT have been written to localStorage as a side
    // effect of clicking the X icon inside the row.
    expect(localStorage.getItem('pa:sel:scan')).toBeNull()
  })
})
