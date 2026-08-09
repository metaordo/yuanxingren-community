import React, { useRef, useState } from 'react'

const NETWORK_TYPES = [
  { value: 'url', label: 'URL', placeholder: 'https://example.com/api' },
  { value: 'ip', label: 'IP / CIDR', placeholder: '192.168.1.0/24' },
  { value: 'domain', label: '域名', placeholder: 'example.com' },
  { value: 'protocol', label: '协议端点', placeholder: 'tcp://host:9000' },
]

const FILE_TYPE_LABEL: Record<string, string> = {
  source: '源代码',
  binary: '二进制',
  pcap: '抓包',
  archive: '压缩包',
  document: '文档',
  other: '其它',
}

function formatBytes(n: number) {
  if (n < 1024) return n + ' B'
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB'
  return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB'
}

const MAX_FILES = 1
const MAX_BYTES = 200 * 1024 * 1024

interface UploadInfo {
  id: number
  filename: string
  file_type: string
  size_bytes: number
}

export default function TargetInput() {
  const [tab, setTab] = useState<'network' | 'upload'>('network')
  const [type, setType] = useState('url')
  const [value, setValue] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  // Upload-as-target state
  const fileRef = useRef<HTMLInputElement | null>(null)
  const [pending, setPending] = useState<UploadInfo | null>(null)
  const [uploading, setUploading] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const [uploadAuthorized, setUploadAuthorized] = useState(false)

  const submitNetwork = async (e: React.FormEvent) => {
    e.preventDefault()
    setMsg(null)
    if (!authorized) {
      setMsg({ text: '请确认已获得目标授权', ok: false })
      return
    }
    setBusy(true)
    try {
      const resp = await fetch('/targets', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value, type_hint: type, authorized: true }),
      })
      const data = await resp.json()
      if (!resp.ok) {
        let text = data.detail || '创建失败'
        if (typeof text === 'string' && text.includes('out of authorized scope')) {
          text += '。请到 设置 → 授权范围 添加该地址或网段。'
        }
        setMsg({ text, ok: false })
      } else {
        setMsg({ text: `目标 #${data.id} 已创建，请到 扫描 / 多 Agent / 对话 页面选用`, ok: true })
        window.dispatchEvent(new CustomEvent('pa:target_created', { detail: { id: data.id } }))
        setValue('')
      }
    } finally {
      setBusy(false)
    }
  }

  const handleFile = async (files: FileList | null) => {
    if (!files || files.length === 0) return
    const f = files[0]
    if (f.size > MAX_BYTES) {
      setMsg({ text: `文件超过 200MB 限制（${formatBytes(f.size)}）`, ok: false })
      return
    }
    setMsg(null)
    setUploading(true)
    const fd = new FormData()
    fd.append('files', f)
    try {
      const resp = await fetch('/api/uploads', {
        method: 'POST',
        credentials: 'include',
        body: fd,
      })
      if (!resp.ok) {
        let text = '上传失败'
        if (resp.status === 413) text = '文件过大，服务器拒绝接收'
        else {
          try { text = (await resp.json()).detail || text } catch {}
        }
        setMsg({ text, ok: false })
        return
      }
      const data = await resp.json()
      const u = data.uploads?.[0]
      if (u) {
        setPending({
          id: u.id,
          filename: u.filename,
          file_type: u.file_type,
          size_bytes: u.size_bytes,
        })
      }
    } catch (e: any) {
      setMsg({ text: e.message || '上传失败', ok: false })
    } finally {
      setUploading(false)
    }
  }

  const submitUploadTarget = async () => {
    if (!pending) return
    setMsg(null)
    if (!uploadAuthorized) {
      setMsg({ text: '请确认已获得授权', ok: false })
      return
    }
    setBusy(true)
    try {
      const resp = await fetch('/targets/from-upload', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ upload_id: pending.id, authorized: true }),
      })
      const data = await resp.json()
      if (!resp.ok) {
        setMsg({ text: data.detail || '创建失败', ok: false })
      } else {
        setMsg({ text: `目标 #${data.id} 已创建，请到 扫描 / 多 Agent / 对话 页面选用`, ok: true })
        window.dispatchEvent(new CustomEvent('pa:target_created', { detail: { id: data.id } }))
        setPending(null)
        setUploadAuthorized(false)
      }
    } finally {
      setBusy(false)
    }
  }

  const current = NETWORK_TYPES.find(t => t.value === type) || NETWORK_TYPES[0]

  return (
    <div className="card p-6">
      <div className="mb-5">
        <h3 className="text-base font-semibold text-brand-text">目标配置</h3>
        <p className="mt-1 text-sm text-brand-secondary">定义授权的测试目标范围</p>
      </div>

      {/* Tabs */}
      <div className="mb-5 flex gap-1 rounded-xl bg-brand-bg2 p-1">
        <button
          type="button"
          onClick={() => { setTab('network'); setMsg(null) }}
          className={`flex-1 rounded-lg px-3 py-2 text-sm transition ${
            tab === 'network'
              ? 'bg-white text-brand-text shadow-sm font-medium'
              : 'text-brand-secondary hover:text-brand-text'
          }`}
        >
          网络目标
        </button>
        <button
          type="button"
          onClick={() => { setTab('upload'); setMsg(null) }}
          className={`flex-1 rounded-lg px-3 py-2 text-sm transition ${
            tab === 'upload'
              ? 'bg-white text-brand-text shadow-sm font-medium'
              : 'text-brand-secondary hover:text-brand-text'
          }`}
        >
          上传文件
        </button>
      </div>

      {tab === 'network' ? (
        <form onSubmit={submitNetwork} className="space-y-4">
          <div>
            <label className="mb-2 block text-sm font-medium text-brand-text">目标类型</label>
            <div className="grid grid-cols-2 gap-2">
              {NETWORK_TYPES.map(t => (
                <button
                  type="button"
                  key={t.value}
                  onClick={() => setType(t.value)}
                  className={`rounded-xl border px-3 py-2.5 text-sm transition-all ${
                    type === t.value
                      ? 'border-brand-primary bg-brand-primaryLight text-brand-primary font-medium'
                      : 'border-brand-border bg-white text-brand-secondary hover:bg-brand-bg2'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="mb-2 block text-sm font-medium text-brand-text">{current.label}</label>
            <input
              value={value}
              onChange={e => setValue(e.target.value)}
              placeholder={current.placeholder}
              className="input-field"
              required
            />
          </div>

          <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-brand-border bg-brand-bg2 p-4">
            <input
              type="checkbox"
              checked={authorized}
              onChange={e => setAuthorized(e.target.checked)}
              className="mt-0.5"
            />
            <span className="text-sm text-brand-text">
              我确认该目标在授权渗透测试范围内
            </span>
          </label>

          {msg && (
            <div className={`rounded-xl px-4 py-3 text-sm ${
              msg.ok
                ? 'border border-brand-success/20 bg-brand-successLight text-brand-success'
                : 'border border-brand-danger/20 bg-brand-dangerLight text-brand-danger'
            }`}>
              {msg.ok ? '✓' : '✗'} {msg.text}
            </div>
          )}

          <button type="submit" disabled={busy} className="btn-primary w-full">
            {busy ? '正在创建...' : '设置目标'}
          </button>
        </form>
      ) : (
        <div className="space-y-4">
          <p className="text-xs text-brand-secondary leading-relaxed">
            支持上传：源代码（.c / .py / .go / ... ）、压缩包（.zip / .tar.gz）、
            二进制（ELF / PE）、抓包（.pcap）、文档（.pdf / .docx）。
            上传后会创建对应类型的目标，并自动加入对话上下文用于后续分析。
          </p>

          {/* Drag & drop / file picker */}
          {!pending ? (
            <div
              className={`relative rounded-xl border-2 border-dashed p-8 text-center transition-all ${
                dragOver
                  ? 'border-brand-primary bg-brand-primaryLight/30'
                  : 'border-brand-border bg-brand-bg2 hover:border-brand-primary/50'
              }`}
              onDragOver={e => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={e => {
                e.preventDefault(); setDragOver(false)
                handleFile(e.dataTransfer.files)
              }}
            >
              <input
                ref={fileRef}
                type="file"
                className="hidden"
                onChange={e => { handleFile(e.target.files); e.target.value = '' }}
              />
              <svg className="mx-auto h-10 w-10 text-brand-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3" />
              </svg>
              <div className="mt-3 text-sm text-brand-text">
                {uploading ? '正在上传...' : '点击或拖拽文件到此处'}
              </div>
              <div className="mt-1 text-xs text-brand-muted">单文件最大 200MB</div>
              <button
                type="button"
                onClick={() => fileRef.current?.click()}
                disabled={uploading}
                className="btn-secondary mt-4"
              >
                {uploading ? '上传中...' : '选择文件'}
              </button>
            </div>
          ) : (
            <div className="rounded-xl border border-brand-primaryBorder bg-brand-primaryLight p-4">
              <div className="flex items-start gap-3">
                <svg className="mt-0.5 h-5 w-5 shrink-0 text-brand-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m5.231 13.481L15 17.25m-.5-1.5-2.621 2.121a.875.875 0 0 1-1.236-1.236L13 14.25m0 0L11.5 12.75M13 14.25h-1.5m1.5 0V12.75M9 12.75v3m0 0v-3m0 3h-2.25M19.5 8.25v6.75A2.25 2.25 0 0 1 17.25 17.25H6.75A2.25 2.25 0 0 1 4.5 15V5.25A2.25 2.25 0 0 1 6.75 3h7.5L19.5 8.25Z" />
                </svg>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-brand-text">{pending.filename}</div>
                  <div className="mt-0.5 text-xs text-brand-secondary">
                    {FILE_TYPE_LABEL[pending.file_type] || pending.file_type} · {formatBytes(pending.size_bytes)}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => { setPending(null); setUploadAuthorized(false) }}
                  className="rounded-lg p-1 text-brand-muted hover:bg-white hover:text-brand-danger"
                  title="移除"
                >
                  <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
          )}

          {pending && (
            <>
              <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-brand-border bg-brand-bg2 p-4">
                <input
                  type="checkbox"
                  checked={uploadAuthorized}
                  onChange={e => setUploadAuthorized(e.target.checked)}
                  className="mt-0.5"
                />
                <span className="text-sm text-brand-text">
                  我确认对该文件（及其内容）拥有合法的分析授权
                </span>
              </label>

              <button
                type="button"
                onClick={submitUploadTarget}
                disabled={busy}
                className="btn-primary w-full"
              >
                {busy ? '正在创建...' : '设置为分析目标'}
              </button>
            </>
          )}

          {msg && (
            <div className={`rounded-xl px-4 py-3 text-sm ${
              msg.ok
                ? 'border border-brand-success/20 bg-brand-successLight text-brand-success'
                : 'border border-brand-danger/20 bg-brand-dangerLight text-brand-danger'
            }`}>
              {msg.ok ? '✓' : '✗'} {msg.text}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
