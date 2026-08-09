import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../api/auth'
import BrandMark from '../components/BrandMark'

async function fetchCaptcha(): Promise<{ token: string; image: string }> {
  const resp = await fetch('/auth/captcha', { credentials: 'omit' })
  if (!resp.ok) throw new Error('captcha failed')
  const data = await resp.json()
  return { token: data.captcha_token, image: data.image_b64 }
}

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [captchaToken, setCaptchaToken] = useState('')
  const [captchaImage, setCaptchaImage] = useState('')
  const [captchaAnswer, setCaptchaAnswer] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { login } = useAuth()
  const navigate = useNavigate()

  const refreshCaptcha = async () => {
    setCaptchaAnswer('')
    try {
      const { token, image } = await fetchCaptcha()
      setCaptchaToken(token)
      setCaptchaImage(image)
    } catch {
      setError('验证码加载失败')
    }
  }

  useEffect(() => { refreshCaptcha() }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(username, password, captchaToken, captchaAnswer)
      navigate('/')
    } catch (err: any) {
      setError(err.message || '认证失败')
      refreshCaptcha()
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-brand-bg2">
      {/* Subtle background pattern */}
      <div className="pointer-events-none absolute inset-0 opacity-[0.015]"
           style={{ backgroundImage: 'radial-gradient(circle at 1px 1px, #121419 1px, transparent 0)', backgroundSize: '40px 40px' }} />

      <div className="relative z-10 w-full max-w-md px-6">
        {/* Brand header */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-6 inline-flex items-center justify-center">
            <BrandMark size={192} variant="outline" detail />
          </div>
          <h1 className="flex items-center justify-center text-7xl font-bold tracking-[0.35em] pl-[0.35em]">
            <span className="text-brand-text">元星</span>
            <span className="text-brand-primary">刃</span>
          </h1>
          <p className="mt-5 text-sm font-medium text-brand-secondary">
            AI 驱动的多模态网络攻防平台
          </p>
        </div>

        {/* Login card */}
        <div className="card p-8 animate-slide-up">
          <h2 className="mb-6 text-lg font-semibold text-brand-text">登录系统</h2>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="mb-2 block text-sm font-medium text-brand-text">
                用户名
              </label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="input-field"
                placeholder="请输入用户名"
                autoComplete="username"
                required
              />
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium text-brand-text">
                密码
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="input-field"
                placeholder="请输入密码"
                autoComplete="current-password"
                required
              />
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium text-brand-text">
                验证码
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={captchaAnswer}
                  onChange={e => setCaptchaAnswer(e.target.value.replace(/\s/g, '').toUpperCase().slice(0, 4))}
                  className="input-field flex-1"
                  placeholder="输入图片中的字符"
                  autoComplete="off"
                  maxLength={4}
                  required
                />
                <button
                  type="button"
                  onClick={refreshCaptcha}
                  className="shrink-0 overflow-hidden rounded-lg border border-brand-border hover:border-brand-primary transition-colors"
                  title="点击刷新"
                >
                  {captchaImage ? (
                    <img
                      src={`data:image/png;base64,${captchaImage}`}
                      alt="验证码"
                      className="h-10 w-[100px] object-cover"
                    />
                  ) : (
                    <div className="h-10 w-[100px] flex items-center justify-center bg-brand-bg3 text-brand-muted text-xs">
                      加载中
                    </div>
                  )}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded-xl border border-brand-danger/20 bg-brand-dangerLight px-4 py-3 text-sm text-brand-danger">
                <svg className="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z" />
                </svg>
                <span>{error}</span>
              </div>
            )}

            <button type="submit" disabled={loading} className="btn-primary w-full">
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  登录中...
                </span>
              ) : (
                '登录'
              )}
            </button>
          </form>
        </div>

        <p className="mt-6 text-center text-xs text-brand-muted">
          v0.2.0 · 仅限授权人员访问
        </p>
      </div>
    </div>
  )
}
