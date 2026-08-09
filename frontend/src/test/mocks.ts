import { vi } from 'vitest'

export interface FixtureTarget {
  id: number
  type: string
  value: string
  authorized: boolean
}

export const sampleTargets: FixtureTarget[] = [
  { id: 1, type: 'url', value: 'https://sina.com', authorized: true },
  { id: 2, type: 'ip', value: '10.0.0.1', authorized: true },
  { id: 3, type: 'source', value: 'uploads/3/x.zip', authorized: true },
  { id: 4, type: 'binary', value: 'uploads/4/elf', authorized: true },
  { id: 5, type: 'domain', value: 'example.com', authorized: true },
  { id: 6, type: 'pcap', value: 'uploads/6/cap.pcap', authorized: true },
]

export function mockTargetsFetch(targets: FixtureTarget[] = sampleTargets) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input: any) => {
    const url = typeof input === 'string' ? input : input.url
    if (url.includes('/targets')) {
      return Promise.resolve(new Response(JSON.stringify(targets), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
    }
    return Promise.resolve(new Response('{}', { status: 200 }))
  })
}
