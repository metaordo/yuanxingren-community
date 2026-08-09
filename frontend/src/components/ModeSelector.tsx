import React from 'react'
import { useAppState } from '../api/appState'

export default function ModeSelector() {
  const { mode, setMode } = useAppState()

  return (
    <div className="card p-6">
      <div className="mb-5">
        <h3 className="text-base font-semibold text-brand-text">分析模式</h3>
        <p className="mt-1 text-sm text-brand-secondary">选择测试执行策略</p>
      </div>

      <div className="space-y-3">
        <button
          type="button"
          onClick={() => setMode('engine')}
          className={`w-full rounded-2xl border p-4 text-left transition-all ${
            mode === 'engine'
              ? 'border-brand-primary bg-brand-primaryLight'
              : 'border-brand-border bg-white hover:bg-brand-bg2'
          }`}
        >
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-sm font-medium text-brand-text">深度引擎分析</div>
              <div className="mt-1 text-sm text-brand-secondary">
                调用 SVF、StateAFL、Off-Path 与外部工具，多引擎协同验证。
              </div>
            </div>
            <div className={`mt-1 h-3 w-3 rounded-full ${mode === 'engine' ? 'bg-brand-primary' : 'bg-brand-border'}`} />
          </div>
        </button>

        <button
          type="button"
          onClick={() => setMode('direct')}
          className={`w-full rounded-2xl border p-4 text-left transition-all ${
            mode === 'direct'
              ? 'border-brand-primary bg-brand-primaryLight'
              : 'border-brand-border bg-white hover:bg-brand-bg2'
          }`}
        >
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-sm font-medium text-brand-text">LLM 直接审计</div>
              <div className="mt-1 text-sm text-brand-secondary">
                基于 LLM 与知识库直接分析，适合快速研判与问答。
              </div>
            </div>
            <div className={`mt-1 h-3 w-3 rounded-full ${mode === 'direct' ? 'bg-brand-primary' : 'bg-brand-border'}`} />
          </div>
        </button>
      </div>
    </div>
  )
}
