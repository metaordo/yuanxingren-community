import { useEffect, useRef, useState } from 'react'
import type { Target } from '../api/targetSelection'

export function TargetPicker({
  targets, selectedId, disabled = false, onSelect, onDelete,
}: {
  targets: Target[]
  selectedId: number | null
  disabled?: boolean
  onSelect: (id: number | null) => void
  onDelete?: (id: number) => void | Promise<void>
}) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDocClick = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false)
    }
    const onEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDocClick)
    document.addEventListener('keydown', onEsc)
    return () => {
      document.removeEventListener('mousedown', onDocClick)
      document.removeEventListener('keydown', onEsc)
    }
  }, [open])

  const selected = selectedId !== null ? targets.find(t => t.id === selectedId) : null
  const label = selected ? `#${selected.id} ${selected.value}` : '— 暂不选择 —'

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-2 rounded border border-brand-border bg-white px-2 py-1 text-sm text-brand-text hover:border-brand-primary/50 disabled:opacity-50 disabled:cursor-not-allowed min-w-[240px]"
      >
        <span className="flex-1 truncate text-left">{label}</span>
        <svg className={`h-3.5 w-3.5 shrink-0 text-brand-muted transition-transform ${open ? 'rotate-180' : ''}`}
             fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
        </svg>
      </button>

      {open && (
        <div className="absolute z-20 mt-1 w-full min-w-[320px] max-h-72 overflow-y-auto rounded border border-brand-border bg-white shadow-lg">
          <div
            role="option"
            onClick={() => { onSelect(null); setOpen(false) }}
            className={`flex items-center px-3 py-2 text-sm cursor-pointer hover:bg-brand-bg2 ${
              selectedId === null ? 'bg-brand-primaryLight text-brand-primary font-medium' : 'text-brand-secondary'
            }`}
          >
            — 暂不选择 —
          </div>
          {targets.length === 0 && (
            <div className="px-3 py-2 text-xs text-brand-muted italic">
              无 source 目标 — 请先到目标配置上传
            </div>
          )}
          {targets.map(t => {
            const isSel = t.id === selectedId
            return (
              <div
                key={t.id}
                role="option"
                onClick={() => { onSelect(t.id); setOpen(false) }}
                className={`group flex items-center gap-2 px-3 py-2 text-sm cursor-pointer hover:bg-brand-bg2 ${
                  isSel ? 'bg-brand-primaryLight text-brand-primary font-medium' : 'text-brand-text'
                }`}
              >
                <span className="flex-1 truncate">#{t.id} {t.value}</span>
                {onDelete && (
                  <button
                    type="button"
                    title={`删除目标 #${t.id}（仅删记录,上传文件保留）`}
                    onClick={(e) => { e.stopPropagation(); onDelete(t.id) }}
                    className="opacity-0 group-hover:opacity-100 focus:opacity-100 flex h-5 w-5 shrink-0 items-center justify-center rounded text-brand-muted hover:bg-brand-danger hover:text-white transition-colors"
                    aria-label={`删除目标 #${t.id}`}
                  >
                    <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
                    </svg>
                  </button>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
