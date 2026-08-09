import React, { useEffect, useRef, useState } from 'react'
import { Scope, useTargetSelection } from '../api/targetSelection'

interface Props {
  scope: Scope
  /** Optional override for the empty-state placeholder text. */
  emptyHint?: string
}

/** Compact target switcher for pages that need to pick from the user's
 *  existing targets within a given scope. The list is filtered by ACCEPT[scope]
 *  upstream in TargetSelectionProvider; this component only renders + writes.
 */
export default function TargetSwitcher({ scope, emptyHint }: Props) {
  const { targets, selected, select } = useTargetSelection(scope)
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

  const label = selected
    ? `#${selected.id} ${selected.value}`
    : '— 选择目标 —'

  const pick = (t: typeof selected) => {
    select(t)
    setOpen(false)
  }

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="flex w-full items-center gap-2 rounded border border-brand-border bg-white px-3 py-1.5 text-sm text-brand-text hover:border-brand-primary/50 min-w-[240px]"
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
            onClick={() => pick(null)}
            className={`flex items-center px-3 py-2 text-sm cursor-pointer hover:bg-brand-bg2 ${
              !selected ? 'bg-brand-primaryLight text-brand-primary font-medium' : 'text-brand-secondary'
            }`}
          >
            — 暂不选择 —
          </div>
          {targets.length === 0 && (
            <div className="px-3 py-2 text-xs text-brand-muted italic">
              {emptyHint || '没有可用目标 — 请到 设置 → 目标配置 创建'}
            </div>
          )}
          {targets.map(t => {
            const isSel = selected?.id === t.id
            const onDelete = async (e: React.MouseEvent) => {
              e.stopPropagation()
              if (!window.confirm(
                `确认删除目标 #${t.id}（${t.value}）？\n该操作只移除目标记录，上传文件本体保留。`
              )) return
              try {
                const resp = await fetch(`/targets/${t.id}`, {
                  method: 'DELETE', credentials: 'include',
                })
                if (!resp.ok) {
                  const data = await resp.json().catch(() => ({}))
                  window.alert(data.detail || `删除失败 (HTTP ${resp.status})`)
                  return
                }
                // Provider listens for this event and refreshes + reconciles —
                // if the deleted target was the current selection, it auto-clears.
                window.dispatchEvent(new CustomEvent('pa:target_deleted', { detail: { id: t.id } }))
              } catch (err: any) {
                window.alert(err?.message || '删除失败')
              }
            }
            return (
              <div
                key={t.id}
                role="option"
                onClick={() => pick(t)}
                className={`group flex items-center gap-2 px-3 py-2 text-sm cursor-pointer hover:bg-brand-bg2 ${
                  isSel ? 'bg-brand-primaryLight text-brand-primary font-medium' : 'text-brand-text'
                }`}
              >
                <span className="badge badge-info shrink-0">{t.type}</span>
                <span className="flex-1 truncate">#{t.id} {t.value}</span>
                <button
                  type="button"
                  onClick={onDelete}
                  title={`删除目标 #${t.id}（仅删记录，上传文件保留）`}
                  aria-label={`删除目标 #${t.id}`}
                  className="opacity-0 group-hover:opacity-100 focus:opacity-100 flex h-5 w-5 shrink-0 items-center justify-center rounded text-brand-muted hover:bg-brand-danger hover:text-white transition-colors"
                >
                  <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
