import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import './index.css'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import { AuthProvider, useAuth } from './api/auth'
import { AppStateProvider } from './api/appState'
import { TargetSelectionProvider } from './api/targetSelection'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="flex h-screen items-center justify-center">加载中...</div>
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <AppStateProvider>
          <TargetSelectionProvider>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
            </Routes>
          </TargetSelectionProvider>
        </AppStateProvider>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
