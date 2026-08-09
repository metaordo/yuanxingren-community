import { describe, test, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import CompliancePanel from './CompliancePanel'

vi.mock('../api/targetSelection', () => ({
  useTargetSelection: () => ({
    targets: [{ id: 7, type: 'source', value: 'proj.zip' }],
    selected: { id: 7, value: 'proj.zip', type: 'source' },
    select: vi.fn(),
  }),
}))

describe('CompliancePanel', () => {
  beforeEach(() => {
    global.fetch = vi.fn(() =>
      Promise.resolve({ ok: true, json: () => Promise.resolve({ scan_id: 1 }) })) as any
  })

  test('点开始检查先弹同意框,未同意不发 scan 请求', async () => {
    render(<CompliancePanel />)
    fireEvent.click(screen.getByText(/开始合规检查/))
    expect(screen.getByText(/结构指纹/)).toBeTruthy()
    expect(global.fetch).not.toHaveBeenCalledWith('/api/compliance/scan', expect.anything())
  })

  test('点同意后才发起扫描请求', async () => {
    render(<CompliancePanel />)
    fireEvent.click(screen.getByText(/开始合规检查/))
    fireEvent.click(screen.getByText(/同意并继续/))
    await waitFor(() =>
      expect(global.fetch).toHaveBeenCalledWith(
        '/api/compliance/scan', expect.objectContaining({ method: 'POST' })))
  })

  test('面板不出现第三方服务名', () => {
    const { container } = render(<CompliancePanel />)
    expect(container.innerHTML.toLowerCase()).not.toContain('scanoss')
    expect(container.innerHTML.toLowerCase()).not.toContain('osskb')
  })
})
