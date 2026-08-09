import React, { useEffect, useState } from 'react'

interface Hit {
  id: string
  title: string
  type: string
  category: string
  year: number | null
  summary: string
  url: string | null
}

interface Entry {
  id: string
  title: string
  type: string
  category: string
  year: number | null
  venue: string | null
  url: string | null
  summary: string
  attack_surface: string[]
  mitigations: string[]
  cves: string[]
}

interface CweNode {
  id: string
  name: string
  abstraction: string
  status: string
  has_children: boolean
  parents: string[]
}

interface CweConsequence { scope: string[]; impact: string[]; note: string }
interface CweMitigation { phase: string[]; strategy: string; description: string; effectiveness: string }
interface CweDetection { method: string; description: string; effectiveness: string }
interface CweExample { intro_text: string; body_markdown: string; languages: string[] }
interface CwePlatform { name?: string; class?: string; prevalence?: string }

interface CweFull {
  id: string
  name: string
  abstraction: string
  structure: string
  status: string
  description: string
  extended_description: string
  likelihood: string | null
  parents: string[]
  children: string[]
  peers: string[]
  consequences: CweConsequence[]
  mitigations: CweMitigation[]
  detection_methods: CweDetection[]
  demonstrative_examples: CweExample[]
  applicable_platforms: {
    languages: CwePlatform[]
    oses: CwePlatform[]
    architectures: CwePlatform[]
    technologies: CwePlatform[]
  }
  capec_ids: string[]
  references: { id: string; section: string }[]
}

type Tab = 'search' | 'browse' | 'cwe'

const TAB_LABELS: Record<Tab, string> = {
  search: '搜索',
  browse: '协议文献',
  cwe: 'CWE',
}

export default function KnowledgePanel() {
  const [tab, setTab] = useState<Tab>('search')

  // Search tab state (unchanged behavior from previous version)
  const [query, setQuery] = useState('')
  const [hits, setHits] = useState<Hit[]>([])
  const [busy, setBusy] = useState(false)

  // Browse tab state — lazily populated on first switch
  const [allEntries, setAllEntries] = useState<Entry[] | null>(null)
  const [loadingAll, setLoadingAll] = useState(false)
  const [loadError, setLoadError] = useState<string>('')
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set())
  const [expandedEntries, setExpandedEntries] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (tab !== 'browse' || allEntries !== null || loadingAll) return
    setLoadingAll(true)
    setLoadError('')
    fetch('/api/knowledge/list', { credentials: 'include' })
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then(d => setAllEntries(d.entries || []))
      .catch(err => setLoadError(err?.message || '加载失败'))
      .finally(() => setLoadingAll(false))
  }, [tab, allEntries, loadingAll])

  const retryLoadAll = () => {
    setLoadError('')
    setAllEntries(null)
  }

  // CWE tab state
  const [cwePillars, setCwePillars] = useState<CweNode[] | null>(null)
  const [cwePillarsLoading, setCwePillarsLoading] = useState(false)
  const [cwePillarsError, setCwePillarsError] = useState<string>('')
  const [cweExpanded, setCweExpanded] = useState<Map<string, CweNode[]>>(new Map())
  const [cweDetail, setCweDetail] = useState<CweFull | null>(null)
  const [cweDetailLoading, setCweDetailLoading] = useState(false)
  const [cweQuery, setCweQuery] = useState('')
  const [cweHits, setCweHits] = useState<CweNode[] | null>(null)
  const [cweSearching, setCweSearching] = useState(false)
  const [cweTotal, setCweTotal] = useState<number | null>(null)

  // Eagerly fetch the CWE total so the header summary line can render even on
  // first paint (before user has opened the CWE tab). Uses /list?abstraction=
  // — server returns the full corpus count without enumerating it (we only
  // read .total, ignoring .entries).
  useEffect(() => {
    fetch('/api/cwe/list', { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d && typeof d.total === 'number') setCweTotal(d.total) })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (tab !== 'cwe' || cwePillars !== null || cwePillarsLoading) return
    setCwePillarsLoading(true)
    setCwePillarsError('')
    fetch('/api/cwe/tree/roots', { credentials: 'include' })
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then(d => setCwePillars(d.roots || []))
      .catch(err => setCwePillarsError(err?.message || '加载失败'))
      .finally(() => setCwePillarsLoading(false))
  }, [tab, cwePillars, cwePillarsLoading])

  const retryLoadCwe = () => {
    setCwePillarsError('')
    setCwePillars(null)
  }

  const fetchCweChildren = async (parentId: string): Promise<CweNode[]> => {
    if (cweExpanded.has(parentId)) return cweExpanded.get(parentId)!
    const r = await fetch(`/api/cwe/list?parent_id=${encodeURIComponent(parentId)}`,
                         { credentials: 'include' })
    const d = r.ok ? await r.json() : { entries: [] }
    const kids: CweNode[] = d.entries || []
    setCweExpanded(prev => {
      const next = new Map(prev)
      next.set(parentId, kids)
      return next
    })
    return kids
  }

  const fetchCweDetail = async (cweId: string) => {
    setCweDetailLoading(true)
    try {
      const r = await fetch(`/api/cwe/${encodeURIComponent(cweId)}`,
                           { credentials: 'include' })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const d = await r.json()
      setCweDetail(d.entry)
    } catch {
      setCweDetail(null)
    } finally {
      setCweDetailLoading(false)
    }
  }

  const runCweSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!cweQuery.trim()) {
      setCweHits(null)
      return
    }
    setCweSearching(true)
    try {
      const r = await fetch(`/api/cwe/search?q=${encodeURIComponent(cweQuery)}&top_k=30`,
                           { credentials: 'include' })
      const d = r.ok ? await r.json() : { hits: [] }
      setCweHits(d.hits || [])
    } finally {
      setCweSearching(false)
    }
  }

  const search = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!query.trim()) return
    setBusy(true)
    try {
      const resp = await fetch('/api/knowledge/search?q=' + encodeURIComponent(query),
        { credentials: 'include' })
      const data = resp.ok ? await resp.json() : { hits: [] }
      setHits(data.hits || [])
    } finally {
      setBusy(false)
    }
  }

  const toggleGroup = (key: string) => {
    setExpandedGroups(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key); else next.add(key)
      return next
    })
  }
  const toggleEntry = (id: string) => {
    setExpandedEntries(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  const totalLabel = allEntries
    ? `共 ${allEntries.length} 条`
    : '403 条学术文献与 CVE 数据索引'
  const cweLabel = cweTotal !== null
    ? `${cweTotal} 条通用漏洞模式与索引`
    : '通用漏洞模式与索引'

  return (
    <div className="space-y-5">
      <div>
        <h3 className="text-base font-semibold text-brand-text">协议栈知识库</h3>
        <p className="mt-1 text-sm text-brand-secondary">{totalLabel}</p>
        <h3 className="mt-3 text-base font-semibold text-brand-text">通用弱点枚举（CWE）</h3>
        <p className="mt-1 text-sm text-brand-secondary">{cweLabel}</p>
      </div>

      {/* Tab header */}
      <div className="flex gap-1 border-b border-brand-border">
        {(['search', 'browse', 'cwe'] as const).map(t => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`relative px-4 py-2 text-sm transition ${
              tab === t
                ? 'font-medium text-brand-primary'
                : 'text-brand-secondary hover:text-brand-text'
            }`}
          >
            {TAB_LABELS[t]}
            {tab === t && (
              <span className="absolute inset-x-2 -bottom-px h-[2px] bg-brand-primary" />
            )}
          </button>
        ))}
      </div>

      {tab === 'search' ? (
        <SearchView
          query={query} setQuery={setQuery}
          hits={hits} busy={busy} onSubmit={search}
        />
      ) : tab === 'browse' ? (
        <BrowseView
          entries={allEntries}
          loading={loadingAll}
          error={loadError}
          expandedGroups={expandedGroups}
          expandedEntries={expandedEntries}
          onToggleGroup={toggleGroup}
          onToggleEntry={toggleEntry}
          onRetry={retryLoadAll}
        />
      ) : (
        <CweView
          pillars={cwePillars}
          loading={cwePillarsLoading}
          error={cwePillarsError}
          expanded={cweExpanded}
          detail={cweDetail}
          detailLoading={cweDetailLoading}
          query={cweQuery}
          setQuery={setCweQuery}
          hits={cweHits}
          searching={cweSearching}
          onRetry={retryLoadCwe}
          onFetchChildren={fetchCweChildren}
          onFetchDetail={fetchCweDetail}
          onRunSearch={runCweSearch}
          onCloseDetail={() => setCweDetail(null)}
        />
      )}
    </div>
  )
}

function SearchView({ query, setQuery, hits, busy, onSubmit }: {
  query: string
  setQuery: (s: string) => void
  hits: Hit[]
  busy: boolean
  onSubmit: (e: React.FormEvent) => void
}) {
  return (
    <>
      <form onSubmit={onSubmit} className="flex gap-2">
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="搜索：TCP 序列号预测、TLS 降级..."
          className="input-field flex-1"
        />
        <button type="submit" disabled={busy} className="btn-primary shrink-0 px-4">
          {busy ? (
            <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
          ) : '搜索'}
        </button>
      </form>

      <div className="space-y-3 max-h-[600px] overflow-y-auto">
        {hits.map(h => (
          <div key={h.id} className="card card-hover p-4">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="badge badge-info">{h.type}</span>
              <span className="badge badge-low">{h.category}</span>
              {h.year && <span className="text-xs text-brand-muted">{h.year}</span>}
            </div>
            <div className="text-sm font-medium text-brand-text">{h.title}</div>
            {h.url && (
              <a href={h.url} target="_blank" rel="noreferrer"
                 className="mt-2 inline-flex items-center gap-1 text-xs text-brand-primary hover:underline">
                查看来源
                <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 0 0 3 8.25v10.5A2.25 2.25 0 0 0 5.25 21h10.5A2.25 2.25 0 0 0 18 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
                </svg>
              </a>
            )}
          </div>
        ))}
        {hits.length === 0 && !busy && (
          <div className="py-12 text-center">
            <svg className="mx-auto mb-3 h-10 w-10 text-brand-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 6.042A8.967 8.967 0 0 0 6 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 0 1 6 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 0 1 6-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0 0 18 18a8.967 8.967 0 0 0-6 2.292m0-14.25v14.25" />
            </svg>
            <p className="text-sm text-brand-muted">输入关键词搜索知识库</p>
          </div>
        )}
      </div>
    </>
  )
}

interface BrowseViewProps {
  entries: Entry[] | null
  loading: boolean
  error: string
  expandedGroups: Set<string>
  expandedEntries: Set<string>
  onToggleGroup: (key: string) => void
  onToggleEntry: (id: string) => void
  onRetry: () => void
}

/** Group entries by category, returning [categoryName, list] tuples sorted
 *  by entry count descending. The "General" bucket is always pushed to the
 *  end regardless of size — it is the unclassified catch-all and would
 *  otherwise dominate the top of the list. */
function groupByCategory(entries: Entry[]): [string, Entry[]][] {
  const map = new Map<string, Entry[]>()
  for (const e of entries) {
    const list = map.get(e.category)
    if (list) list.push(e); else map.set(e.category, [e])
  }
  const ordered = [...map.entries()].sort((a, b) => {
    if (a[0] === 'General') return 1
    if (b[0] === 'General') return -1
    return b[1].length - a[1].length
  })
  return ordered
}

/** For the "General" group only: subdivide by entry type, sorted by count desc. */
function groupByType(entries: Entry[]): [string, Entry[]][] {
  const map = new Map<string, Entry[]>()
  for (const e of entries) {
    const list = map.get(e.type)
    if (list) list.push(e); else map.set(e.type, [e])
  }
  return [...map.entries()].sort((a, b) => b[1].length - a[1].length)
}

function Chevron({ open, size = 'sm' }: { open: boolean; size?: 'sm' | 'xs' }) {
  const cls = size === 'xs' ? 'h-3 w-3' : 'h-4 w-4'
  return (
    <svg
      className={`${cls} shrink-0 text-brand-muted transition-transform ${open ? 'rotate-90' : ''}`}
      fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.25}
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
    </svg>
  )
}

function EntryCard({ entry, expanded, onToggle }: {
  entry: Entry
  expanded: boolean
  onToggle: () => void
}) {
  const hasDetail = entry.summary
    || entry.attack_surface.length > 0
    || entry.mitigations.length > 0
    || entry.cves.length > 0
    || entry.url
  return (
    <div className="rounded-lg border border-brand-border bg-white">
      <button
        type="button"
        onClick={hasDetail ? onToggle : undefined}
        disabled={!hasDetail}
        className={`flex w-full items-start gap-2 px-3 py-2 text-left ${
          hasDetail ? 'hover:bg-brand-surface/50' : 'cursor-default'
        }`}
      >
        {hasDetail ? (
          <Chevron open={expanded} size="xs" />
        ) : (
          <span className="h-3 w-3 shrink-0" aria-hidden />
        )}
        <div className="min-w-0 flex-1">
          <div className="mb-1 flex flex-wrap items-center gap-1.5">
            <span className="badge badge-info">{entry.type}</span>
            {entry.year && (
              <span className="text-xs text-brand-muted">{entry.year}</span>
            )}
            {entry.venue && (
              <span className="text-xs text-brand-muted">· {entry.venue}</span>
            )}
          </div>
          <div className="text-sm font-medium text-brand-text">{entry.title}</div>
        </div>
      </button>
      {expanded && hasDetail && (
        <div className="space-y-2 border-t border-brand-border bg-brand-surface/40 px-3 py-3 text-xs">
          {entry.summary && (
            <div className="text-brand-text leading-relaxed">{entry.summary}</div>
          )}
          {entry.attack_surface.length > 0 && (
            <div>
              <span className="text-brand-muted">攻击面：</span>
              {entry.attack_surface.map((s, i) => (
                <span key={i} className="ml-1 inline-block rounded bg-brand-primaryLight px-1.5 py-0.5 text-brand-primary">
                  {s}
                </span>
              ))}
            </div>
          )}
          {entry.mitigations.length > 0 && (
            <div>
              <span className="text-brand-muted">缓解：</span>
              {entry.mitigations.map((m, i) => (
                <span key={i} className="ml-1 inline-block rounded bg-brand-surface px-1.5 py-0.5 text-brand-text">
                  {m}
                </span>
              ))}
            </div>
          )}
          {entry.cves.length > 0 && (
            <div className="text-brand-muted">
              CVE：<span className="text-brand-text">{entry.cves.join(', ')}</span>
            </div>
          )}
          {entry.url && (
            <a href={entry.url} target="_blank" rel="noreferrer"
               className="inline-flex items-center gap-1 text-brand-primary hover:underline">
              查看来源
              <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 0 0 3 8.25v10.5A2.25 2.25 0 0 0 5.25 21h10.5A2.25 2.25 0 0 0 18 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
              </svg>
            </a>
          )}
        </div>
      )}
    </div>
  )
}

function BrowseView({
  entries, loading, error,
  expandedGroups, expandedEntries,
  onToggleGroup, onToggleEntry, onRetry,
}: BrowseViewProps) {
  if (loading) {
    return (
      <div className="flex items-center gap-2 py-12 text-sm text-brand-muted">
        <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        正在加载知识库索引…
      </div>
    )
  }
  if (error) {
    return (
      <div className="flex items-center justify-between gap-3 rounded-lg border border-brand-danger/40 bg-brand-dangerLight px-3 py-2 text-xs text-brand-danger">
        <span className="truncate">✗ {error}</span>
        <button
          type="button"
          onClick={onRetry}
          className="shrink-0 rounded border border-brand-danger/40 bg-white px-2 py-0.5 text-brand-danger hover:bg-brand-danger hover:text-white"
        >
          重试
        </button>
      </div>
    )
  }
  if (!entries || entries.length === 0) {
    return <div className="py-12 text-center text-sm text-brand-muted">知识库为空</div>
  }

  const grouped = groupByCategory(entries)

  return (
    <div className="space-y-2 max-h-[640px] overflow-y-auto pr-1">
      {grouped.map(([cat, list]) => {
        const open = expandedGroups.has(cat)
        return (
          <div key={cat} className="rounded-xl border border-brand-border bg-brand-surface">
            <button
              type="button"
              onClick={() => onToggleGroup(cat)}
              className="flex w-full items-center gap-2 px-3.5 py-2.5 text-left hover:bg-brand-surface/70"
            >
              <Chevron open={open} />
              <div className="flex-1 text-sm font-medium text-brand-text">{cat}</div>
              <div className="text-xs text-brand-muted">{list.length} 条</div>
            </button>
            {open && (
              <div className="space-y-1.5 px-3 pb-3">
                {cat === 'General' ? (
                  <GeneralSubGroups
                    list={list}
                    expandedGroups={expandedGroups}
                    expandedEntries={expandedEntries}
                    onToggleGroup={onToggleGroup}
                    onToggleEntry={onToggleEntry}
                  />
                ) : (
                  list.map(e => (
                    <EntryCard
                      key={e.id}
                      entry={e}
                      expanded={expandedEntries.has(e.id)}
                      onToggle={() => onToggleEntry(e.id)}
                    />
                  ))
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

function GeneralSubGroups({
  list, expandedGroups, expandedEntries,
  onToggleGroup, onToggleEntry,
}: {
  list: Entry[]
  expandedGroups: Set<string>
  expandedEntries: Set<string>
  onToggleGroup: (key: string) => void
  onToggleEntry: (id: string) => void
}) {
  const subgroups = groupByType(list)
  return (
    <>
      {subgroups.map(([type, items]) => {
        const subKey = `General::${type}`
        const open = expandedGroups.has(subKey)
        return (
          <div key={subKey} className="rounded-lg border border-brand-border bg-white">
            <button
              type="button"
              onClick={() => onToggleGroup(subKey)}
              className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-brand-surface/50"
            >
              <Chevron open={open} size="xs" />
              <div className="flex-1 text-sm text-brand-text">{type}</div>
              <div className="text-xs text-brand-muted">{items.length} 条</div>
            </button>
            {open && (
              <div className="space-y-1.5 px-3 pb-3">
                {items.map(e => (
                  <EntryCard
                    key={e.id}
                    entry={e}
                    expanded={expandedEntries.has(e.id)}
                    onToggle={() => onToggleEntry(e.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )
      })}
    </>
  )
}

interface CweViewProps {
  pillars: CweNode[] | null
  loading: boolean
  error: string
  expanded: Map<string, CweNode[]>
  detail: CweFull | null
  detailLoading: boolean
  query: string
  setQuery: (s: string) => void
  hits: CweNode[] | null
  searching: boolean
  onRetry: () => void
  onFetchChildren: (parentId: string) => Promise<CweNode[]>
  onFetchDetail: (cweId: string) => void
  onRunSearch: (e: React.FormEvent) => void
  onCloseDetail: () => void
}

function CweView(p: CweViewProps) {
  if (p.loading) {
    return (
      <div className="flex items-center gap-2 py-12 text-sm text-brand-muted">
        <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        正在加载 CWE 树根…
      </div>
    )
  }
  if (p.error) {
    return (
      <div className="flex items-center justify-between gap-3 rounded-lg border border-brand-danger/40 bg-brand-dangerLight px-3 py-2 text-xs text-brand-danger">
        <span className="truncate">✗ {p.error}</span>
        <button type="button" onClick={p.onRetry}
          className="shrink-0 rounded border border-brand-danger/40 bg-white px-2 py-0.5 text-brand-danger hover:bg-brand-danger hover:text-white">
          重试
        </button>
      </div>
    )
  }
  if (!p.pillars || p.pillars.length === 0) {
    return <div className="py-12 text-center text-sm text-brand-muted">CWE 数据库为空</div>
  }
  return (
    <div className="space-y-3">
      {/* Search box (CWE-scoped) */}
      <form onSubmit={p.onRunSearch} className="flex gap-2">
        <input
          value={p.query}
          onChange={e => p.setQuery(e.target.value)}
          placeholder="搜索 CWE：xss / sql injection / buffer overflow..."
          className="input-field flex-1"
        />
        <button type="submit" disabled={p.searching} className="btn-primary shrink-0 px-4">
          {p.searching ? '...' : '搜索'}
        </button>
      </form>
      {/* Either search results or full tree */}
      {p.hits !== null ? (
        <div className="space-y-2 max-h-[640px] overflow-y-auto pr-1">
          <div className="text-xs text-brand-muted">{p.hits.length} 条命中</div>
          {p.hits.map(h => (
            <CweRow key={h.id} node={h} level={0}
              onClickDetail={() => p.onFetchDetail(h.id)} />
          ))}
        </div>
      ) : (
        <div className="space-y-1 max-h-[640px] overflow-y-auto pr-1">
          {p.pillars.map(pl => (
            <CweTreeNode key={pl.id} node={pl} level={0}
              expanded={p.expanded}
              onFetchChildren={p.onFetchChildren}
              onClickDetail={p.onFetchDetail} />
          ))}
        </div>
      )}
      {/* Detail panel */}
      {(p.detail || p.detailLoading) && (
        <CweDetail entry={p.detail} loading={p.detailLoading} onClose={p.onCloseDetail} />
      )}
    </div>
  )
}

function CweRow({ node, level, onClickDetail }: {
  node: CweNode
  level: number
  onClickDetail: () => void
}) {
  return (
    <div className="rounded border border-brand-border bg-white"
         style={{ marginLeft: level * 16 }}>
      <button type="button" onClick={onClickDetail}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-brand-surface/50">
        <span className="badge badge-info">{node.abstraction}</span>
        <span className="text-sm font-medium text-brand-text">{node.id}</span>
        <span className="text-sm text-brand-text truncate flex-1">{node.name}</span>
      </button>
    </div>
  )
}

function CweTreeNode({
  node, level, expanded, onFetchChildren, onClickDetail,
}: {
  node: CweNode
  level: number
  expanded: Map<string, CweNode[]>
  onFetchChildren: (id: string) => Promise<CweNode[]>
  onClickDetail: (id: string) => void
}) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const kids = expanded.get(node.id)

  const handleToggle = async (e: React.MouseEvent) => {
    e.stopPropagation()
    if (!node.has_children) return
    if (!open && kids === undefined) {
      setLoading(true)
      try { await onFetchChildren(node.id) } finally { setLoading(false) }
    }
    setOpen(!open)
  }

  return (
    <div>
      <div className="flex items-center gap-1 rounded border border-brand-border bg-white hover:bg-brand-surface/30"
           style={{ marginLeft: level * 16 }}>
        <button type="button" onClick={handleToggle}
          disabled={!node.has_children}
          className={`flex h-7 w-7 shrink-0 items-center justify-center ${
            node.has_children ? 'hover:bg-brand-surface/60' : 'cursor-default'
          }`}
          aria-label={node.has_children ? (open ? '折叠' : '展开') : ''}
        >
          {node.has_children && (
            loading ? (
              <svg className="h-3 w-3 animate-spin text-brand-muted" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            ) : (
              <Chevron open={open} size="xs" />
            )
          )}
        </button>
        <button type="button" onClick={() => onClickDetail(node.id)}
          className="flex-1 flex items-center gap-2 px-2 py-2 text-left">
          <span className="badge badge-info">{node.abstraction}</span>
          <span className="text-sm font-medium text-brand-text">{node.id}</span>
          <span className="text-sm text-brand-text truncate flex-1">{node.name}</span>
        </button>
      </div>
      {open && kids?.map(k => (
        <CweTreeNode key={k.id} node={k} level={level + 1}
          expanded={expanded}
          onFetchChildren={onFetchChildren}
          onClickDetail={onClickDetail} />
      ))}
    </div>
  )
}

function CweDetail({ entry, loading, onClose }: {
  entry: CweFull | null
  loading: boolean
  onClose: () => void
}) {
  // Close on Escape.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="flex max-h-[85vh] w-full max-w-3xl flex-col overflow-hidden rounded-xl border-2 border-brand-primary bg-white shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex shrink-0 items-center justify-between border-b border-brand-border bg-brand-primaryLight px-5 py-3">
          <div className="truncate pr-3 text-base font-semibold text-brand-primary">
            {loading ? '加载中…' : entry ? `${entry.id} · ${entry.name}` : 'CWE 详情'}
          </div>
          <button type="button" onClick={onClose}
            aria-label="关闭"
            className="shrink-0 rounded p-1 text-brand-secondary hover:bg-white hover:text-brand-text">
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        {loading ? (
          <div className="px-5 py-8 text-sm text-brand-muted">正在加载详情…</div>
        ) : entry ? (
          <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4 text-sm">
            <div className="flex flex-wrap gap-2">
              <span className="badge badge-info">{entry.abstraction}</span>
              <span className="badge badge-low">{entry.status}</span>
              {entry.likelihood && <span className="badge badge-low">利用可能性 {entry.likelihood}</span>}
              {entry.structure && <span className="badge badge-low">{entry.structure}</span>}
            </div>
            {entry.description && (
              <div>
                <div className="mb-1 text-xs font-medium text-brand-muted">描述</div>
                <div className="leading-relaxed text-brand-text">{entry.description}</div>
              </div>
            )}
            {entry.extended_description && (
              <div>
                <div className="mb-1 text-xs font-medium text-brand-muted">扩展描述</div>
                <div className="whitespace-pre-wrap leading-relaxed text-brand-text">{entry.extended_description}</div>
              </div>
            )}
            {(entry.parents.length > 0 || entry.children.length > 0 || entry.peers.length > 0) && (
              <div className="space-y-1 text-xs">
                {entry.parents.length > 0 && (
                  <div><span className="text-brand-muted">父类：</span>{entry.parents.join(', ')}</div>
                )}
                {entry.children.length > 0 && (
                  <div><span className="text-brand-muted">子类：</span>{entry.children.join(', ')}</div>
                )}
                {entry.peers.length > 0 && (
                  <div><span className="text-brand-muted">同侪/相关：</span>{entry.peers.join(', ')}</div>
                )}
              </div>
            )}
            {entry.consequences.length > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium text-brand-muted">常见后果</div>
                <table className="w-full border-collapse text-xs">
                  <thead>
                    <tr className="text-left text-brand-muted">
                      <th className="border border-brand-border px-2 py-1">范围</th>
                      <th className="border border-brand-border px-2 py-1">影响</th>
                      <th className="border border-brand-border px-2 py-1">说明</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entry.consequences.map((c, i) => (
                      <tr key={i}>
                        <td className="border border-brand-border px-2 py-1 align-top">{c.scope.join(', ')}</td>
                        <td className="border border-brand-border px-2 py-1 align-top">{c.impact.join(', ')}</td>
                        <td className="border border-brand-border px-2 py-1 align-top">{c.note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {entry.mitigations.length > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium text-brand-muted">缓解措施</div>
                <ul className="space-y-2 text-xs">
                  {entry.mitigations.map((m, i) => (
                    <li key={i} className="rounded bg-brand-surface/50 p-2">
                      <div className="font-medium text-brand-text">
                        {m.strategy || m.phase.join(' / ') || '通用'}
                        {m.effectiveness && <span className="ml-2 text-brand-muted">({m.effectiveness})</span>}
                      </div>
                      <div className="mt-1 text-brand-text">{m.description}</div>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {entry.demonstrative_examples.length > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium text-brand-muted">代码示例</div>
                {entry.demonstrative_examples.map((ex, i) => (
                  <div key={i} className="mb-3">
                    {ex.intro_text && <div className="mb-1 text-xs text-brand-text">{ex.intro_text}</div>}
                    <pre className="overflow-x-auto whitespace-pre-wrap rounded bg-brand-surface/60 p-2 text-[11px] text-brand-text">{ex.body_markdown}</pre>
                  </div>
                ))}
              </div>
            )}
            {entry.detection_methods.length > 0 && (
              <div>
                <div className="mb-1 text-xs font-medium text-brand-muted">检测方法</div>
                <ul className="space-y-2 text-xs">
                  {entry.detection_methods.map((d, i) => (
                    <li key={i} className="rounded bg-brand-surface/50 p-2">
                      <div className="font-medium text-brand-text">
                        {d.method}{d.effectiveness && <span className="ml-2 text-brand-muted">({d.effectiveness})</span>}
                      </div>
                      <div className="mt-1 text-brand-text">{d.description}</div>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {entry.capec_ids.length > 0 && (
              <div className="text-xs">
                <span className="text-brand-muted">相关攻击模式：</span>
                {entry.capec_ids.map(c => <span key={c} className="ml-1 inline-block rounded bg-brand-primaryLight px-1.5 py-0.5 text-brand-primary">CAPEC-{c}</span>)}
              </div>
            )}
          </div>
        ) : null}
      </div>
    </div>
  )
}
