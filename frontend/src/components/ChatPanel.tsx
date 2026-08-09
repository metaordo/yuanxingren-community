import React, { useEffect, useRef, useState } from 'react'
import ReactMarkdown from 'react-markdown'

interface Finding {
  id: string
  title: string
  severity: string
  category: string
}

interface UploadInfo {
  id: number
  filename: string
  file_type: string
  size_bytes: number
}

interface Message {
  role: 'user' | 'assistant'
  content: string
  steps?: string[]
  findings?: Finding[]
  uploads?: UploadInfo[]
  streaming?: boolean
}

const STEP_LABEL: Record<string, string> = {
  thinking: '分析中',
  planner: '规划任务',
  router: '调度引擎',
  verifier: '交叉验证',
  reporter: '生成报告',
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

const SEVERITY_LABEL: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '提示',
}

const FILE_TYPE_LABEL: Record<string, string> = {
  source: '源代码',
  binary: '二进制',
  pcap: '抓包',
  archive: '压缩包',
  document: '文档',
  other: '其它',
}

const FILE_TYPE_ICON: Record<string, string> = {
  source: 'M3.75 3.75v16.5h16.5V3.75H3.75Zm5.61 11.46-2.04-2.04 2.04-2.04m4.86 4.08 2.04-2.04-2.04-2.04m-1.41 4.8 1.32-7.2',
  binary: 'M2.25 7.5l9 5.25 9-5.25M2.25 7.5l9-5.25 9 5.25M2.25 7.5v9l9 5.25 9-5.25v-9',
  pcap: 'M2.25 12.75c4.5-3 8-3 11.5 0s7 3 11.5 0',
  archive: 'M21.75 17.25v-.228a4.5 4.5 0 0 0-.12-1.03l-2.268-9.64a3.375 3.375 0 0 0-3.285-2.602H7.923a3.375 3.375 0 0 0-3.285 2.602l-2.268 9.64a4.5 4.5 0 0 0-.12 1.03v.228m19.5 0a3 3 0 0 1-3 3H5.25a3 3 0 0 1-3-3m19.5 0a3 3 0 0 0-3-3H5.25a3 3 0 0 0-3 3m16.5 0h.008v.008h-.008v-.008Zm-3 0h.008v.008h-.008v-.008Z',
  document: 'M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25M9 16.5v.75m3-3v3M15 12v5.25m-4.5-15H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z',
  other: 'M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25M15 8.25v-3a2.25 2.25 0 0 0-2.25-2.25H6.75A2.25 2.25 0 0 0 4.5 5.25v13.5A2.25 2.25 0 0 0 6.75 21h10.5A2.25 2.25 0 0 0 19.5 18.75V11.25A2.25 2.25 0 0 0 17.25 9H15Z',
}

function formatBytes(n: number) {
  if (n < 1024) return n + ' B'
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB'
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB'
}

const MAX_FILES = 5
const MAX_BYTES = 200 * 1024 * 1024

const SUGGESTIONS = [
  '介绍一下你最擅长的能力',
  '讲讲 TCP ISN 预测攻击的原理',
  '常见的 Web 漏洞类型和检测思路',
  '怎么用你做一次完整的渗透测试',
]

export default function ChatPanel() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [uploads, setUploads] = useState<UploadInfo[]>([])
  const [uploading, setUploading] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const scrollRef = useRef<HTMLDivElement | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [messages])

  const handleFileSelect = async (files: FileList | null) => {
    if (!files || files.length === 0) return
    if (files.length > MAX_FILES) {
      alert(`最多同时上传 ${MAX_FILES} 个文件`)
      return
    }
    for (let i = 0; i < files.length; i++) {
      if (files[i].size > MAX_BYTES) {
        alert(`文件 ${files[i].name} 超过 200MB 限制`)
        return
      }
    }
    setUploading(true)
    const formData = new FormData()
    for (let i = 0; i < files.length; i++) {
      formData.append('files', files[i])
    }
    try {
      const resp = await fetch('/api/uploads', {
        method: 'POST',
        credentials: 'include',
        body: formData,
      })
      if (!resp.ok) {
        let errMsg = '上传失败'
        if (resp.status === 413) {
          errMsg = '文件过大，服务器拒绝接收'
        } else {
          try {
            const err = await resp.json()
            errMsg = err.detail || `上传失败 (${resp.status})`
          } catch {
            errMsg = `上传失败 (${resp.status})`
          }
        }
        alert(errMsg)
        return
      }
      const data = await resp.json()
      setUploads(prev => [...prev, ...data.uploads])
    } catch (e: any) {
      alert('上传失败: ' + e.message)
    } finally {
      setUploading(false)
    }
  }

  const removeUpload = (id: number) => {
    setUploads(prev => prev.filter(u => u.id !== id))
  }

  const submit = (text: string) => {
    if (!text.trim() || busy) return

    const userMsg: Message = { role: 'user', content: text, uploads: uploads.length > 0 ? [...uploads] : undefined }
    const assistantMsg: Message = { role: 'assistant', content: '', steps: [], findings: [], streaming: true }
    setMessages(prev => [...prev, userMsg, assistantMsg])
    setInput('')
    const uploadIds = uploads.map(u => u.id)
    setUploads([])
    setBusy(true)

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${proto}//${window.location.host}/api/chat/stream`
    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    const updateLast = (mut: (m: Message) => Message) => {
      setMessages(prev => {
        const next = prev.slice()
        next[next.length - 1] = mut(next[next.length - 1])
        return next
      })
    }

    // Track which pipeline step is currently "running" so we can transition
    // it to "done" when the backend announces the next step. Backend `step`
    // events are emitted at each phase's START (planner → router → verifier
    // → reporter / thinking), so the natural model is: receive step N → mark
    // N running + mark N-1 done.
    let lastRunningStep: string | null = null

    ws.onopen = () => {
      // Reset the global workflow-progress panel for this new run
      window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
        detail: { reset: true },
      }))
      ws.send(JSON.stringify({
        message: userMsg.content,
        target_id: null,
        mode: 'direct',
        upload_ids: uploadIds,
      }))
    }
    ws.onmessage = (ev) => {
      const evt = JSON.parse(ev.data)
      if (evt.event === 'step') {
        updateLast(m => ({
          ...m,
          steps: [...(m.steps || []), STEP_LABEL[evt.node] || evt.node]
        }))
        // Mark the previous step done, then light the new one as running.
        if (lastRunningStep && lastRunningStep !== evt.node) {
          window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
            detail: { stepId: lastRunningStep, status: 'done' },
          }))
        }
        window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
          detail: { stepId: evt.node, status: 'running' },
        }))
        lastRunningStep = evt.node
      } else if (evt.event === 'token') {
        updateLast(m => ({ ...m, content: (m.content || '') + evt.chunk }))
      } else if (evt.event === 'finding') {
        updateLast(m => ({ ...m, findings: [...(m.findings || []), evt.finding] }))
      } else if (evt.event === 'done') {
        updateLast(m => ({
          ...m,
          content: evt.reply || m.content,
          findings: evt.findings || m.findings,
          streaming: false,
        }))
        // Close out the last running step (reporter for engine, thinking for
        // direct — both reach the same end state).
        if (lastRunningStep) {
          window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
            detail: { stepId: lastRunningStep, status: 'done' },
          }))
        }
        // And always finalize the terminal "reporter" step. Direct mode never
        // emits a `step` for reporter, so this is the only signal that lights
        // it up; engine mode already has it done above (no-op duplicate).
        window.dispatchEvent(new CustomEvent('pa:workflow_progress', {
          detail: { stepId: 'reporter', status: 'done' },
        }))
        window.dispatchEvent(new CustomEvent('pa:findings', { detail: evt.findings || [] }))
      } else if (evt.event === 'error') {
        updateLast(m => ({
          ...m,
          content: (m.content || '') + (m.content ? '\n\n' : '') + '⚠️ ' + evt.detail,
          streaming: false,
        }))
      }
    }
    ws.onerror = () => fallbackToPost(userMsg, updateLast, uploadIds)
    ws.onclose = () => {
      setBusy(false)
      updateLast(m => ({ ...m, streaming: false }))
    }
  }

  const fallbackToPost = async (
    userMsg: Message,
    updateLast: (m: (m: Message) => Message) => void,
    uploadIds: number[],
  ) => {
    try {
      const resp = await fetch('/api/chat', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userMsg.content,
          target_id: null,
          mode: 'direct',
          upload_ids: uploadIds,
        }),
      })
      const data = resp.ok ? await resp.json() : {
        reply: (await resp.json().catch(() => ({}))).detail || '后端错误',
      }
      updateLast(m => ({
        ...m,
        content: data.reply || '',
        findings: data.findings,
        streaming: false,
      }))
      window.dispatchEvent(new CustomEvent('pa:findings', { detail: data.findings || [] }))
    } catch (err: any) {
      updateLast(m => ({ ...m, content: '✗ ' + err.message, streaming: false }))
    } finally {
      setBusy(false)
    }
  }

  const send = (e: React.FormEvent) => {
    e.preventDefault()
    submit(input)
  }

  return (
    <div className="flex h-full w-full min-w-0 flex-col">
      {/* Messages area */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto">
        {messages.length === 0 ? (
          <div className="flex min-h-full flex-col items-center justify-center px-3 py-8 sm:px-6">
            <div className="mb-6 flex h-16 w-16 items-center justify-center rounded-2xl bg-brand-primaryLight">
              <svg className="h-8 w-8 text-brand-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09ZM18.259 8.715 18 9.75l-.259-1.035a3.375 3.375 0 0 0-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 0 0 2.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 0 0 2.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 0 0-2.456 2.456Z" />
              </svg>
            </div>
            <h2 className="mb-2 text-xl font-semibold text-brand-text">您好，我是元星刃，AI驱动的多模态智能攻防平台！</h2>
            <p className="mb-8 max-w-md text-center text-sm text-brand-secondary">
              描述您的安全测试目标，我将为您规划并执行测试任务
            </p>

            <div className="grid w-full max-w-2xl gap-2.5 sm:grid-cols-2">
              {SUGGESTIONS.map(s => (
                <button
                  key={s}
                  onClick={() => submit(s)}
                  className="card card-hover group flex items-center gap-3 p-4 text-left"
                >
                  <svg className="h-5 w-5 shrink-0 text-brand-muted group-hover:text-brand-primary transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3" />
                  </svg>
                  <span className="text-sm text-brand-text">{s}</span>
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="mx-auto w-full max-w-3xl px-3 py-5 sm:px-6 sm:py-8 xl:max-w-4xl">
            <div className="space-y-6">
              {messages.map((m, i) => (
                <div key={i} className="animate-fade-in">
                  {m.role === 'user' ? (
                    <div className="flex justify-end">
                      <div className="max-w-[92%] rounded-2xl rounded-tr-md bg-brand-primary px-4 py-3 text-sm text-white">
                        <div>{m.content}</div>
                        {m.uploads && m.uploads.length > 0 && (
                          <div className="mt-3 flex flex-wrap gap-2 border-t border-white/20 pt-3">
                            {m.uploads.map(u => (
                              <div key={u.id} className="inline-flex max-w-full items-center gap-2 rounded-xl bg-white/10 px-3 py-2 text-xs text-white/90">
                                <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                                  <path strokeLinecap="round" strokeLinejoin="round" d={FILE_TYPE_ICON[u.file_type] || FILE_TYPE_ICON.other} />
                                </svg>
                                <span className="truncate">{u.filename}</span>
                                <span className="text-white/60">{FILE_TYPE_LABEL[u.file_type] || '文件'} · {formatBytes(u.size_bytes)}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                    <div className="flex gap-3">
                      <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-brand-primaryLight">
                        <svg className="h-4 w-4 text-brand-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09Z" />
                        </svg>
                      </div>
                      <div className="min-w-0 flex-1 space-y-3">
                        {m.steps && m.steps.length > 0 && (
                          <div className="flex flex-wrap gap-1.5">
                            {m.steps.map((s, idx) => (
                              <span key={idx} className="inline-flex items-center gap-1.5 rounded-full bg-brand-successLight px-2.5 py-1 text-xs text-brand-success">
                                <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                                  <path strokeLinecap="round" strokeLinejoin="round" d="m4.5 12.75 6 6 9-13.5" />
                                </svg>
                                {s}
                              </span>
                            ))}
                            {m.streaming && (
                              <span className="inline-flex items-center gap-1.5 rounded-full bg-brand-warningLight px-2.5 py-1 text-xs text-brand-warning">
                                <span className="flex gap-0.5">
                                  <span className="h-1 w-1 animate-typing rounded-full bg-current" style={{ animationDelay: '0ms' }} />
                                  <span className="h-1 w-1 animate-typing rounded-full bg-current" style={{ animationDelay: '200ms' }} />
                                  <span className="h-1 w-1 animate-typing rounded-full bg-current" style={{ animationDelay: '400ms' }} />
                                </span>
                                正在处理
                              </span>
                            )}
                          </div>
                        )}

                        {m.content && (
                          <div className="rounded-2xl rounded-tl-md bg-white border border-brand-border p-4 text-sm text-brand-text prose prose-sm max-w-none">
                            <ReactMarkdown
                              components={{
                                h2: ({node, ...props}) => <h2 className="text-base font-semibold text-brand-text mt-4 mb-2 first:mt-0" {...props} />,
                                h3: ({node, ...props}) => <h3 className="text-sm font-semibold text-brand-text mt-3 mb-1.5" {...props} />,
                                p: ({node, ...props}) => <p className="mb-3 last:mb-0 leading-relaxed" {...props} />,
                                ul: ({node, ...props}) => <ul className="mb-3 space-y-1.5 pl-5 list-disc marker:text-brand-muted" {...props} />,
                                ol: ({node, ...props}) => <ol className="mb-3 space-y-1.5 pl-5 list-decimal marker:text-brand-muted" {...props} />,
                                li: ({node, ...props}) => <li className="leading-relaxed" {...props} />,
                                strong: ({node, ...props}) => <strong className="font-semibold text-brand-text" {...props} />,
                                code: ({node, inline, ...props}: any) =>
                                  inline
                                    ? <code className="rounded bg-brand-bg3 px-1.5 py-0.5 text-xs font-mono text-brand-text" {...props} />
                                    : <code className="block rounded-lg bg-brand-bg3 p-3 text-xs font-mono text-brand-text overflow-x-auto" {...props} />,
                                pre: ({node, ...props}) => <pre className="mb-3 last:mb-0" {...props} />,
                                blockquote: ({node, ...props}) => <blockquote className="border-l-4 border-brand-primary pl-4 italic text-brand-secondary mb-3" {...props} />,
                              }}
                            >
                              {m.content}
                            </ReactMarkdown>
                          </div>
                        )}

                        {m.findings && m.findings.length > 0 && (
                          <div className="rounded-2xl border border-brand-border bg-white p-4">
                            <div className="mb-3 flex items-center justify-between">
                              <span className="text-sm font-medium text-brand-text">安全发现</span>
                              <span className="text-xs text-brand-muted">{m.findings.length} 项</span>
                            </div>
                            <div className="space-y-2">
                              {m.findings.map(f => (
                                <div key={f.id} className="flex items-start gap-3 rounded-xl bg-brand-bg2 p-3">
                                  <span className={`badge ${SEVERITY_BADGE[f.severity] || 'badge-info'}`}>
                                    {SEVERITY_LABEL[f.severity] || f.severity}
                                  </span>
                                  <div className="min-w-0 flex-1">
                                    <div className="truncate text-sm font-medium text-brand-text">{f.title}</div>
                                    <div className="mt-0.5 text-xs text-brand-muted">{f.category}</div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Input area */}
      <div className="border-t border-brand-border bg-white px-3 py-3 sm:px-6 sm:py-4">
        <form onSubmit={send} className="mx-auto w-full max-w-3xl xl:max-w-4xl">
          {/* Upload chips */}
          {uploads.length > 0 && (
            <div className="mb-2 flex flex-wrap gap-2 rounded-xl bg-brand-bg2 p-2.5">
              {uploads.map(u => (
                <div key={u.id} className="inline-flex items-center gap-2 rounded-lg bg-brand-bg3 px-3 py-2 text-xs text-brand-text shadow-sm">
                  <svg className="h-4 w-4 shrink-0 text-brand-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                    <path strokeLinecap="round" strokeLinejoin="round" d={FILE_TYPE_ICON[u.file_type] || FILE_TYPE_ICON.other} />
                  </svg>
                  <span className="max-w-[120px] truncate sm:max-w-[200px]">{u.filename}</span>
                  <span className="text-brand-muted">{FILE_TYPE_LABEL[u.file_type] || '文件'} · {formatBytes(u.size_bytes)}</span>
                  <button
                    type="button"
                    onClick={() => removeUpload(u.id)}
                    className="ml-1 rounded-full p-0.5 text-brand-muted hover:bg-brand-border hover:text-brand-text transition-colors"
                  >
                    <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
                    </svg>
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Drop zone overlay + input box */}
          <div
            className={`relative flex items-end gap-3 rounded-2xl border bg-white px-4 py-3 transition-all ${
              dragOver
                ? 'border-brand-primary bg-brand-primaryLight/30 ring-2 ring-brand-primary/20'
                : busy ? 'border-brand-border' : 'border-brand-border focus-within:border-brand-primary focus-within:shadow-input-focus'
            }`}
            onDragOver={e => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={e => {
              e.preventDefault()
              setDragOver(false)
              handleFileSelect(e.dataTransfer.files)
            }}
          >
            {dragOver && (
              <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-2xl">
                <span className="text-sm font-medium text-brand-primary">拖放文件到此处</span>
              </div>
            )}
            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={e => { handleFileSelect(e.target.files); e.target.value = '' }}
            />
            {/* Upload button */}
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              disabled={busy || uploading}
              className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-all ${
                busy || uploading
                  ? 'bg-brand-bg3 text-brand-muted cursor-not-allowed'
                  : 'bg-brand-bg3 text-brand-secondary hover:bg-brand-border hover:text-brand-text'
              }`}
              title="上传文件 (源代码 / 二进制 / 压缩包)"
            >
              {uploading ? (
                <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : (
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="m18.375 12.739-7.693 7.693a4.5 4.5 0 0 1-6.364-6.364l10.94-10.94A3 3 0 1 1 19.5 7.372L8.552 18.32m.009-.01-.01.01m5.699-9.941-7.81 7.81a1.5 1.5 0 0 0 2.112 2.13" />
                </svg>
              )}
            </button>
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  submit(input)
                }
              }}
              disabled={busy}
              placeholder="向元星刃描述您的安全需求..."
              rows={1}
              className="min-w-0 flex-1 resize-none border-0 bg-transparent text-sm text-brand-text placeholder:text-brand-muted focus:outline-none"
              style={{ maxHeight: '240px' }}
            />
            <button
              type="submit"
              disabled={busy || !input.trim()}
              className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-all ${
                busy || !input.trim()
                  ? 'bg-brand-bg3 text-brand-muted cursor-not-allowed'
                  : 'bg-brand-primary text-white hover:bg-brand-primaryHover'
              }`}
            >
              {busy ? (
                <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : (
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 19.5 19.5 4.5m0 0H8.25m11.25 0v11.25" />
                </svg>
              )}
            </button>
          </div>
          <div className="mt-2 flex items-center justify-between px-1 text-xs text-brand-muted">
            <span>Enter 发送 · Shift+Enter 换行</span>
            <span>支持上传源代码、二进制、压缩包等附件</span>
          </div>
        </form>
      </div>
    </div>
  )
}
