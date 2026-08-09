import React, {
  createContext, useContext, useState, useEffect, useCallback, ReactNode,
} from 'react'

export type Scope = 'scan' | 'multi_agent' | 'chat' | 'compliance' /* | 'agent_audit' */

export const ACCEPT: Record<Scope, string[]> = {
  scan: ['url', 'ip', 'domain', 'protocol'],
  multi_agent: ['source', 'binary', 'pcap'],
  chat: ['url', 'ip', 'domain', 'protocol', 'source', 'binary', 'pcap'],
  compliance: ['source'],
  /* agent_audit: ['source'], */
}

export interface Target {
  id: number
  type: string
  value: string
  authorized?: boolean
}

interface ScopeView {
  targets: Target[]
  selected: Target | null
  select: (t: Target | null) => void
}

const SCOPES: Scope[] = ['scan', 'multi_agent', 'chat', 'compliance' /* , 'agent_audit' */]

function storageKey(scope: Scope): string {
  return `pa:sel:${scope}`
}

function loadPersisted(scope: Scope): Target | null {
  try {
    const raw = localStorage.getItem(storageKey(scope))
    if (!raw) return null
    const t = JSON.parse(raw)
    if (typeof t?.id === 'number' && typeof t?.type === 'string'
        && typeof t?.value === 'string') {
      return t
    }
  } catch {}
  return null
}

function writePersisted(scope: Scope, t: Target | null) {
  try {
    if (t) localStorage.setItem(storageKey(scope), JSON.stringify(t))
    else localStorage.removeItem(storageKey(scope))
  } catch {}
}

type AllTargetsState = Target[]
type SelectedMap = Record<Scope, Target | null>

interface ProviderValue {
  allTargets: AllTargetsState
  selected: SelectedMap
  select: (scope: Scope, t: Target | null) => void
}

const Ctx = createContext<ProviderValue | undefined>(undefined)

export function TargetSelectionProvider({ children }: { children: ReactNode }) {
  const [allTargets, setAllTargets] = useState<AllTargetsState>([])
  const [selected, setSelected] = useState<SelectedMap>(() => ({
    scan: loadPersisted('scan'),
    multi_agent: loadPersisted('multi_agent'),
    chat: loadPersisted('chat'),
    compliance: loadPersisted('compliance'),
    /* agent_audit: loadPersisted('agent_audit'), */
  }))

  const select = useCallback((scope: Scope, t: Target | null) => {
    setSelected(prev => ({ ...prev, [scope]: t }))
    writePersisted(scope, t)
  }, [])

  // After every refresh, validate each scope's selection against the new list
  // and against the scope's ACCEPT types. Drop stale ids and wrong types.
  const reconcile = useCallback((rows: Target[]) => {
    setSelected(prev => {
      const next = { ...prev }
      for (const s of SCOPES) {
        const cur = prev[s]
        if (!cur) continue
        const stillExists = rows.some(r => r.id === cur.id)
        const typeOk = ACCEPT[s].includes(cur.type)
        if (!stillExists || !typeOk) {
          next[s] = null
          writePersisted(s, null)
        }
      }
      return next
    })
  }, [])

  // Initial fetch + listen for cross-page create/delete events.
  useEffect(() => {
    let cancelled = false
    const refresh = () => {
      fetch('/targets', { credentials: 'include' })
        .then(r => r.ok ? r.json() : [])
        .then((rows: Target[]) => {
          if (cancelled) return
          setAllTargets(rows || [])
          reconcile(rows || [])
        })
        .catch(() => {})
    }
    refresh()
    const onChange = () => refresh()
    window.addEventListener('pa:target_created', onChange)
    window.addEventListener('pa:target_deleted', onChange)
    return () => {
      cancelled = true
      window.removeEventListener('pa:target_created', onChange)
      window.removeEventListener('pa:target_deleted', onChange)
    }
  }, [reconcile])

  return (
    <Ctx.Provider value={{ allTargets, selected, select }}>
      {children}
    </Ctx.Provider>
  )
}

export function useTargetSelection(scope: Scope): ScopeView {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useTargetSelection must be used within TargetSelectionProvider')
  const targets = ctx.allTargets.filter(t => ACCEPT[scope].includes(t.type))
  const sel = ctx.selected[scope]
  return {
    targets,
    selected: sel,
    select: (t: Target | null) => ctx.select(scope, t),
  }
}
