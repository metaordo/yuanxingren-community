import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react'

interface User {
  id: number
  username: string
  role: string
  must_change_password: boolean
}

interface AuthContextType {
  user: User | null
  loading: boolean
  login: (username: string, password: string, captcha_token?: string, captcha_answer?: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/auth/me', { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(data => setUser(data))
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [])

  const login = async (username: string, password: string, captcha_token?: string, captcha_answer?: string) => {
    const resp = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password, captcha_token: captcha_token || '', captcha_answer: captcha_answer || '' }),
    })
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ detail: 'login failed' }))
      throw new Error(err.detail || 'login failed')
    }
    const data = await resp.json()
    setUser(data.user)
    if (data.must_change_password) {
      alert('首次登录，请修改密码')
    }
  }

  const logout = async () => {
    await fetch('/auth/logout', { method: 'POST', credentials: 'include' })
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
