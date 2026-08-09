import React, { createContext, useContext, useState, ReactNode } from 'react'

export type Mode = 'engine' | 'direct' | 'multi_agent'

interface AppState {
  mode: Mode
  setMode: (m: Mode) => void
}

const AppStateContext = createContext<AppState | undefined>(undefined)

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<Mode>('direct')
  return (
    <AppStateContext.Provider value={{ mode, setMode }}>
      {children}
    </AppStateContext.Provider>
  )
}

export function useAppState() {
  const ctx = useContext(AppStateContext)
  if (!ctx) throw new Error('useAppState must be used within AppStateProvider')
  return ctx
}
