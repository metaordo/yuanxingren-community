import React, { useEffect, useRef, useState } from 'react'
import { useAuth } from '../api/auth'
import ChatPanel from '../components/ChatPanel'
import TargetInput from '../components/TargetInput'
import ModelPicker from '../components/ModelPicker'
import CustomModelManager from '../components/CustomModelManager'
import KnowledgePanel from '../components/KnowledgePanel'
import AttackGraph from '../components/AttackGraph'
import UserManagement from '../components/UserManagement'
import AuditPanel from '../components/AuditPanel'
import AuthScopeManager from '../components/AuthScopeManager'
import ZapScanPanel from '../components/ZapScanPanel'
import CompliancePanel from '../components/CompliancePanel'
// import AgentAuditPanel from '../components/AgentAuditPanel'
import MultiAgentDashboard from '../components/MultiAgentDashboard'
import BrandMark from '../components/BrandMark'
import { useAppState, type Mode } from '../api/appState'
import { useTargetSelection, type Scope } from '../api/targetSelection'
import {
  usePipelineStates,
  type Source,
  type ReportPayload,
  type StepStatus,
  type ProgressMap,
} from '../api/agentWorkflowBus'
import { usePdfProgress } from '../hooks/usePdfProgress'

function navToSource(nav: NavItem): Source {
  if (nav === 'scan') return 'scan'
  if (nav === 'multi-agent') return 'multi_agent'
  return 'chat'
}

interface StepDef { id: string; label: string; desc: string }

const STEPS_BY_MODE: Record<Mode, StepDef[]> = {
  engine: [
    { id: 'target',   label: '目标',   desc: '' },
    { id: 'planner',  label: '规划器', desc: 'LLM 任务分解' },
    { id: 'router',   label: '路由器', desc: '引擎调度' },
    { id: 'verifier', label: '验证器', desc: '交叉验证' },
    { id: 'reporter', label: '报告器', desc: '生成报告' },
  ],
  direct: [
    { id: 'target',   label: '目标',     desc: '' },
    { id: 'thinking', label: 'LLM 直审', desc: '纯推理 + RAG 增强' },
    { id: 'reporter', label: '报告器',   desc: '生成报告' },
  ],
  multi_agent: [
    { id: 'target',            label: '目标',           desc: '' },
    { id: 'supervisor',        label: 'Supervisor',     desc: 'LLM 动态调度' },
    { id: 'workers',           label: '专项引擎调度',   desc: '8 个分析引擎并行' },
    { id: 'verifier',          label: '三层去重',       desc: 'L1 / L2 / L3 dedupe' },
    { id: 'verifier_reviewer', label: 'LLM 置信裁判',  desc: 'keep / lower / dismiss' },
    { id: 'reporter',          label: '报告生成',       desc: '聚合 + 0-day 闭环' },
  ],
}

// Step list shown when the user is on the Scan tab. ZapScanPanel maps the
// real spider / ascan progress onto these ids via `pa:workflow_progress`.
const SCAN_STEPS: StepDef[] = [
  { id: 'target',   label: '目标',     desc: '' },
  { id: 'spider',   label: 'Spider 爬取',     desc: '抓取站点 URL 图' },
  { id: 'ascan',    label: 'Active Scan',     desc: 'X-Scan 主动扫描' },
  { id: 'reporter', label: '汇总告警',       desc: '聚合 alerts' },
]

type NavItem = 'chat' | 'multi-agent' | /* 'custom-mode' | */ /* 'agent-audit' | */ /* 'custom' | */ 'scan' | 'graph' | 'knowledge' | /* 'audit' | */ 'settings'

export default function Dashboard() {
  const { user, logout } = useAuth()
  const { mode, setMode } = useAppState()
  const pipelines = usePipelineStates()
  const [nav, setNav] = useState<NavItem>('chat')

  // Pick the pipeline state for the current nav (left AgentWorkflow panel).
  const currentSource = navToSource(nav)
  const findings = pipelines[currentSource].findings
  const progress = pipelines[currentSource].progress
  const report = pipelines[currentSource].report

  // Keep global mode in sync with nav. When the user is on the multi-agent
  // tab the AgentWorkflow side panel must show the multi-agent pipeline
  // labels; when they leave for chat we snap mode back to engine so the
  // chat backend doesn't reject `multi_agent` submissions. Now that the
  // multi-agent panel stays mounted across nav switches, we can't rely on
  // its mount-time effect to set mode any more — Dashboard owns this.
  useEffect(() => {
    if (nav === 'multi-agent' && mode !== 'multi_agent') {
      setMode('multi_agent')
    } else if (nav === 'chat' && mode === 'multi_agent') {
      setMode('engine')
    }
  }, [nav, mode, setMode])

  // Nav switching previously broadcast a global reset to clear sidebar state,
  // which clobbered an in-flight multi_agent run when the user peeked at the
  // scan tab. With per-source pipeline state we don't need that reset — each
  // tab's bucket survives nav changes independently.
  const [settingsTab, setSettingsTab] = useState<'target' | 'scope' | 'models' | 'custom' | 'users'>('target')

  const isAdmin = user?.role === 'admin'

  const navItems: { id: NavItem; label: string; icon: JSX.Element; adminOnly?: boolean }[] = [
    {
      id: 'chat', label: '对话',
      icon: <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M7.5 8.25h9m-9 3H12m-9.75 1.51c0 1.6 1.123 2.994 2.707 3.227 1.129.166 2.27.293 3.423.379.35.026.67.21.865.501L12 21l2.755-4.133a1.14 1.14 0 0 1 .865-.501 48.172 48.172 0 0 0 3.423-.379c1.584-.233 2.707-1.626 2.707-3.228V6.741c0-1.602-1.123-2.995-2.707-3.228A48.394 48.394 0 0 0 12 3c-2.392 0-4.744.175-7.043.513C3.373 3.746 2.25 5.14 2.25 6.741v6.018Z" /></svg>,
    },
    {
      id: 'scan', label: '渗透测试',
      icon: <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M3 7.5L7.5 3M3 7.5h4.5M3 7.5v4.5m18 0V7.5L16.5 3M21 7.5h-4.5M3 16.5L7.5 21M3 16.5v-4.5M3 16.5h4.5m13.5 0L16.5 21m4.5-4.5h-4.5m4.5 0v-4.5M10.5 12a1.5 1.5 0 1 1 3 0 1.5 1.5 0 0 1-3 0Z" /></svg>,
    },
    {
      id: 'multi-agent', label: '漏洞挖掘',
      icon: <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 0 0 2.625.372 9.337 9.337 0 0 0 4.121-.952 4.125 4.125 0 0 0-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 0 1 8.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0 1 11.964-3.07M12 6.375a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0Zm8.25 2.25a2.625 2.625 0 1 1-5.25 0 2.625 2.625 0 0 1 5.25 0Z" /></svg>,
    },
    // {
    //   id: 'custom-mode', label: '定制模式',
    //   icon: <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 6.878V6a2.25 2.25 0 0 1 2.25-2.25h7.5A2.25 2.25 0 0 1 18 6v.878m-12 0c.235-.083.487-.128.75-.128h10.5c.263 0 .515.045.75.128m-12 0A2.25 2.25 0 0 0 4.5 9v.878m13.5-3A2.25 2.25 0 0 1 19.5 9v.878m0 0a2.246 2.246 0 0 0-.75-.128H5.25c-.263 0-.515.045-.75.128m15 0A2.25 2.25 0 0 1 21 12v6a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 18v-6c0-.98.626-1.813 1.5-2.122" /></svg>,
    // },
    // {
    //   id: 'agent-audit', label: 'Agent 审计',
    //   icon: <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" /></svg>,
    // },
    // {
    //   id: 'custom', label: '合规检查',
    //   icon: <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M10.5 6h9.75M10.5 6a1.5 1.5 0 1 1-3 0m3 0a1.5 1.5 0 1 0-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 0 1-3 0m3 0a1.5 1.5 0 0 0-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 0 1-3 0m3 0a1.5 1.5 0 0 0-3 0m-9.75 0h9.75" /></svg>,
    // },
    {
      id: 'graph', label: '证据图',
      icon: <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M7.5 14.25v2.25m3-4.5v4.5m3-6.75v6.75m3-9v9M6 20.25h12A2.25 2.25 0 0 0 20.25 18V6A2.25 2.25 0 0 0 18 3.75H6A2.25 2.25 0 0 0 3.75 6v12A2.25 2.25 0 0 0 6 20.25Z" /></svg>,
    },
    {
      id: 'knowledge', label: '知识库',
      icon: <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 6.042A8.967 8.967 0 0 0 6 3.75c-1.052 0-2.062.18-3 .512v14.25A8.987 8.987 0 0 1 6 18c2.305 0 4.408.867 6 2.292m0-14.25a8.966 8.966 0 0 1 6-2.292c1.052 0 2.062.18 3 .512v14.25A8.987 8.987 0 0 0 18 18a8.967 8.967 0 0 0-6 2.292m0-14.25v14.25" /></svg>,
    },
    // {
    //   id: 'audit', label: '审计',
    //   icon: <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" /></svg>,
    //   adminOnly: true,
    // },
    {
      id: 'settings', label: '设置',
      icon: <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281Z" /><path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" /></svg>,
    },
  ]

  return (
    <div className="flex h-screen flex-col bg-brand-bg2">
      {/* Top navigation */}
      <header className="shrink-0 border-b border-brand-border bg-white shadow-nav">
        <div className="flex h-14 items-center justify-between px-3 sm:px-5">
          {/* Left: brand */}
          <div className="flex items-center gap-2 sm:gap-3">
            <BrandMark size={32} variant="outline" className="shrink-0" />
            <div className="hidden sm:flex sm:items-baseline sm:gap-2">
              <span className="text-lg font-bold tracking-[0.2em] text-brand-text pl-[0.2em]">
                元星<span className="text-brand-primary">刃</span>
              </span>
            </div>
          </div>

          {/* Center: nav tabs (desktop) */}
          <nav className="hidden items-center gap-1 md:flex">
            {navItems.map(item => {
              if (item.adminOnly && !isAdmin) return null
              const active = nav === item.id
              return (
                <button
                  key={item.id}
                  onClick={() => setNav(item.id)}
                  className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm transition-all ${
                    active
                      ? 'bg-brand-primaryLight text-brand-primary font-medium'
                      : 'text-brand-secondary hover:bg-brand-bg3 hover:text-brand-text'
                  }`}
                >
                  {item.icon}
                  <span>{item.label}</span>
                </button>
              )
            })}
          </nav>

          {/* Right: status + user */}
          <div className="flex items-center gap-2 sm:gap-4">
            <div className="hidden items-center gap-3 text-xs text-brand-secondary lg:flex">
              <span className="flex items-center gap-1.5">
                <span className="status-dot status-dot-online" />
                引擎在线
              </span>
            </div>

            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-bg3 text-xs font-semibold text-brand-secondary">
                {user?.username?.[0]?.toUpperCase() ?? '?'}
              </div>
              <div className="hidden leading-tight sm:block">
                <div className="text-sm font-medium text-brand-text">{user?.username}</div>
                <div className="text-xs text-brand-muted">{user?.role}</div>
              </div>
              <button onClick={logout} className="btn-ghost ml-1" title="退出登录">
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0 0 13.5 3h-6a2.25 2.25 0 0 0-2.25 2.25v13.5A2.25 2.25 0 0 0 7.5 21h6a2.25 2.25 0 0 0 2.25-2.25V15M12 9l-3 3m0 0 3 3m-3-3h12.75" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Mobile bottom nav */}
      <nav className="fixed bottom-0 left-0 right-0 z-50 flex items-center justify-around border-t border-brand-border bg-white py-2 md:hidden">
        {navItems.map(item => {
          if (item.adminOnly && !isAdmin) return null
          const active = nav === item.id
          return (
            <button
              key={item.id}
              onClick={() => setNav(item.id)}
              className={`flex flex-col items-center gap-0.5 px-2 py-1 text-2xs transition-colors ${
                active ? 'text-brand-primary' : 'text-brand-muted'
              }`}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          )
        })}
      </nav>

      {/* Main content */}
      <main className="flex min-h-0 flex-1 pb-14 md:pb-0">
        <div className={nav === 'chat' ? 'flex min-w-0 flex-1' : 'hidden'}>
          <ChatPanel />
        </div>

        {nav === 'graph' && (
          <div className="flex-1 p-3 sm:p-5">
            <div className="card h-full overflow-hidden">
              <AttackGraph
                findings={findings}
                targetLabel="证据图"
              />
            </div>
          </div>
        )}

        {/* Compliance: Community 版暂时移除
            (state + polling loop + progress) survives the user peeking at other
            tabs. Same persistence pattern as scan/multi-agent below. */}
        {/* <div className={nav === 'custom' ? 'flex-1 p-3 sm:p-5' : 'hidden'}>
          <CompliancePanel />
        </div> */}

        {/* Scan: keep mounted across nav switches so an in-flight ZAP scan
            (and its polling loop) survives the user peeking at other tabs.
            Same pattern as multi-agent below. */}
        <div className={nav === 'scan' ? 'flex min-h-0 flex-1 flex-col' : 'hidden'}>
          <ZapScanPanel />
        </div>

        {/* Multi-agent: keep mounted across nav switches so users can leave
            and return without losing the in-memory dashboard state (runs,
            decisions, report, 0-day cards). Other tabs still use conditional
            rendering — only this one carries enough ephemeral state to warrant
            the persistence. */}
        <div className={nav === 'multi-agent' ? 'flex flex-1' : 'hidden'}>
          {/* Left: Agent workflow panel — same pipeline visualization as chat */}
          <aside className="hidden w-60 shrink-0 border-r border-brand-border bg-white p-4 xl:block">
            <AgentWorkflow mode={mode} findings={findings} progress={progress} report={report} nav={nav} />
          </aside>
          <div className="flex-1">
            <MultiAgentDashboard />
          </div>
        </div>

        {/* {nav === 'custom-mode' && (
          <div className="flex-1 p-3 sm:p-5">
            <CustomModePanel />
          </div>
        )} */}

{/*        <div className={nav === 'agent-audit' ? 'flex-1 p-3 sm:p-5' : 'hidden'}>
          <AgentAuditPanel />
        </div> */}

        {nav === 'knowledge' && (
          <div className="flex-1 p-3 sm:p-5">
            <div className="card h-full overflow-hidden p-4 sm:p-6">
              <KnowledgePanel />
            </div>
          </div>
        )}

        {/* {nav === 'audit' && isAdmin && (
          <div className="flex-1 p-3 sm:p-5">
            <AuditPanel />
          </div>
        )} */}

        {nav === 'settings' && (
          <div className="flex flex-1 flex-col sm:flex-row">
            <aside className="shrink-0 border-b border-brand-border bg-white p-3 sm:w-48 sm:border-b-0 sm:border-r sm:p-4">
              <nav className="flex gap-1 overflow-x-auto sm:flex-col sm:space-y-1 sm:gap-0">
                {[
                  { id: 'target' as const, label: '目标配置' },
                  { id: 'scope' as const, label: '授权范围' },
                  ...(isAdmin ? [{ id: 'models' as const, label: '模型路由' }] : []),
                  ...(isAdmin ? [{ id: 'custom' as const, label: '自定义模型' }] : []),
                  ...(isAdmin ? [{ id: 'users' as const, label: '用户管理' }] : []),
                ].map(item => (
                  <button
                    key={item.id}
                    onClick={() => setSettingsTab(item.id)}
                    className={`whitespace-nowrap rounded-lg px-3 py-2 text-left text-sm transition ${
                      settingsTab === item.id
                        ? 'bg-brand-primaryLight text-brand-primary font-medium'
                        : 'text-brand-secondary hover:bg-brand-bg3 hover:text-brand-text'
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </nav>
            </aside>
            <div className="flex-1 overflow-y-auto p-4 sm:p-6">
              <div className="mx-auto max-w-2xl">
                {settingsTab === 'target' && <TargetInput />}
                {settingsTab === 'scope' && <AuthScopeManager />}
                {settingsTab === 'models' && isAdmin && <ModelPicker />}
                {settingsTab === 'custom' && isAdmin && <CustomModelManager />}
                {settingsTab === 'users' && isAdmin && <UserManagement />}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

/** Synthetic progress for the PDF render endpoint — see hooks/usePdfProgress.tsx */

function AgentWorkflow({ mode, findings, progress, report, nav }: {
  mode: Mode
  findings: any[]
  progress: ProgressMap
  report: ReportPayload | null
  nav: NavItem
}) {
  const scope: Scope = nav === 'scan' ? 'scan'
                     : nav === 'multi-agent' ? 'multi_agent'
                     : 'chat'
  const { selected: activeTarget } = useTargetSelection(scope)
  const stepDefs = nav === 'scan' ? SCAN_STEPS : STEPS_BY_MODE[mode]
  const [generatingPdf, setGeneratingPdf] = useState(false)
  const [pdfError, setPdfError] = useState<string>('')
  const pdfProgress = usePdfProgress(generatingPdf)

  // Pipeline visualization only makes sense when the user is actually about
  // to run / has run an analysis. Direct mode is conversational (single LLM
  // call, no pipeline) and engine mode without a target is just a chat shell.
  // multi-agent mode is purpose-built for analysis, so always show.
  const showPipeline = nav === 'scan'
                     || mode === 'multi_agent'
                     || (mode === 'engine' && !!activeTarget)

  const stepStatus = (id: string): StepStatus => {
    if (id === 'target') return activeTarget ? 'done' : 'pending'
    const explicit = progress[id]
    if (explicit) return explicit
    // Legacy fallback: if any finding has been pushed via pa:findings and the
    // current run did not emit per-step events, treat all post-target steps
    // as done. This preserves the pre-mode-aware behavior for older POST chats.
    if (findings.length > 0) return 'done'
    return 'pending'
  }

  const stepDesc = (def: StepDef): string => {
    if (def.id === 'target') return activeTarget ? activeTarget.value : '未配置'
    if (def.id === 'reporter' && findings.length > 0) {
      return `${findings.length} 个发现`
    }
    return def.desc
  }

  /** Trigger a browser download of the latest report rendered as PDF.
   *
   * Posts the markdown body to the backend `/api/reports/render-pdf` endpoint,
   * which returns a brand-styled application/pdf blob (CJK fonts + pygments
   * code highlighting + page header/footer). The backend names the file via
   * Content-Disposition; we extract that and feed it to the synthetic <a>. */
  const downloadReport = async () => {
    if (!report || !report.content || generatingPdf) return
    setGeneratingPdf(true)
    setPdfError('')
    try {
      const targetLabel = activeTarget
        ? `#${activeTarget.id} ${activeTarget.value}`
        : undefined
      const resp = await fetch('/api/reports/render-pdf', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: report.content,
          mode: report.mode,
          target_label: targetLabel,
        }),
      })
      if (!resp.ok) {
        const errText = await resp.text().catch(() => '')
        throw new Error(`HTTP ${resp.status} · ${errText.slice(0, 200) || '上游错误'}`)
      }
      const blob = await resp.blob()
      // Prefer Content-Disposition filename; fall back to a client-stamped name.
      const cd = resp.headers.get('Content-Disposition') || ''
      const m = /filename="([^"]+)"/.exec(cd)
      const now = new Date()
      const pad = (n: number) => n.toString().padStart(2, '0')
      const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}`
                    + `-${pad(now.getHours())}${pad(now.getMinutes())}`
      const fallback = `pentest-report-${stamp}-${report.mode}.pdf`
      const filename = m ? m[1] : fallback
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err: any) {
      setPdfError(err?.message || '生成 PDF 失败')
    } finally {
      setGeneratingPdf(false)
    }
  }

  return (
    <div className="space-y-5">
      {showPipeline ? (
        <>
          <div>
            <h3 className="text-sm font-semibold text-brand-text">Agent 工作流</h3>
            <p className="mt-1 text-xs text-brand-secondary">
              {mode === 'multi_agent' ? '多 Agent 并行审计流水线' :
                '深度引擎自动化流水线'}
            </p>
          </div>

          <div className="relative space-y-0">
            {stepDefs.map((step, i) => {
              const status = stepStatus(step.id)
              const desc = stepDesc(step)
              const isLast = i === stepDefs.length - 1
              const connectorActive = status === 'done'
              return (
                <div key={step.id} className="relative flex gap-3 pb-6 last:pb-0">
                  {!isLast && (
                    <div className={`absolute left-[11px] top-6 h-full w-px ${connectorActive ? 'bg-brand-primary' : 'bg-brand-border'}`} />
                  )}
                  <div className={`relative z-10 mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border-2 ${
                    status === 'done'
                      ? 'border-brand-primary bg-brand-primary'
                      : status === 'running'
                        ? 'border-brand-primary bg-white'
                        : 'border-brand-border bg-white'
                  }`}>
                    {status === 'done' && (
                      <svg className="h-3 w-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="m4.5 12.75 6 6 9-13.5" />
                      </svg>
                    )}
                    {status === 'running' && (
                      <svg className="h-3 w-3 animate-spin text-brand-primary" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                    )}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className={`text-sm font-medium ${
                      status === 'pending' ? 'text-brand-muted' : 'text-brand-text'
                    }`}>{step.label}</div>
                    <div className="mt-0.5 truncate text-xs text-brand-muted">{desc}</div>
                  </div>
                </div>
              )
            })}
          </div>

          {findings.length > 0 && (
            <div className="rounded-xl border border-brand-primaryBorder bg-brand-primaryLight p-3">
              <div className="flex items-center gap-2 text-sm font-medium text-brand-primary">
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.008v.008H12v-.008Z" />
                </svg>
                发现 {findings.length} 个安全问题
              </div>
            </div>
          )}

          {report && report.content && (
            <div className="space-y-2">
              <button
                type="button"
                onClick={downloadReport}
                disabled={generatingPdf}
                className="group flex w-full items-center justify-between gap-3 rounded-xl border border-brand-primary bg-brand-primary px-3.5 py-3 text-left text-white transition hover:bg-brand-primary/90 disabled:cursor-wait disabled:opacity-80"
              >
                <div className="flex items-center gap-2.5">
                  {generatingPdf ? (
                    <svg className="h-5 w-5 shrink-0 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                  ) : (
                    <svg className="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.75}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3" />
                    </svg>
                  )}
                  <div>
                    <div className="text-sm font-medium">
                      {generatingPdf ? '正在生成 PDF...' : '下载分析报告'}
                    </div>
                    <div className="mt-0.5 text-xs opacity-90">
                      {generatingPdf ? '详见下方进度' : `PDF 格式 · 源文 ${(report.content.length / 1024).toFixed(1)} KB`}
                    </div>
                  </div>
                </div>
                {!generatingPdf && (
                  <svg className="h-4 w-4 shrink-0 opacity-70 transition group-hover:translate-x-0.5 group-hover:opacity-100" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                  </svg>
                )}
              </button>
              {generatingPdf && (
                <div className="rounded-xl border border-brand-border bg-brand-surface px-3.5 py-2.5">
                  <div className="flex items-center justify-between text-xs text-brand-secondary">
                    <span className="truncate pr-2">
                      {pdfProgress.label}
                      <span className="mx-1.5 text-brand-muted">·</span>
                      已耗时 {(pdfProgress.elapsedMs / 1000).toFixed(1)}s
                      {pdfProgress.etaMs !== null && !pdfProgress.frozen && (
                        <>
                          <span className="mx-1.5 text-brand-muted">·</span>
                          约剩 {(pdfProgress.etaMs / 1000).toFixed(1)}s
                        </>
                      )}
                    </span>
                    <span className="shrink-0 tabular-nums text-brand-muted">
                      {pdfProgress.pct.toFixed(0)}%
                    </span>
                  </div>
                  <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-brand-border">
                    <div
                      className="h-full rounded-full bg-brand-primary transition-[width] duration-200 ease-out"
                      style={{ width: `${pdfProgress.pct}%` }}
                    />
                  </div>
                </div>
              )}
              {pdfError && (
                <div className="rounded-lg border border-brand-danger/40 bg-brand-dangerLight px-3 py-2 text-xs text-brand-danger">
                  ✗ {pdfError}
                </div>
              )}
            </div>
          )}
        </>
      ) : (
        // Conversational layout: target chip + mode picker only. No pipeline
        // visualization, no findings chip, no download button.
        <div>
          <h3 className="text-sm font-semibold text-brand-text">已选目标</h3>
          <div className="mt-3 flex items-start gap-2.5">
            <div className={`mt-0.5 h-2.5 w-2.5 shrink-0 rounded-full ${
              activeTarget ? 'bg-brand-primary' : 'bg-brand-border'
            }`} />
            <div className="min-w-0 flex-1">
              <div className={`text-sm ${activeTarget ? 'text-brand-text font-medium' : 'text-brand-muted'}`}>
                {activeTarget ? activeTarget.value : '未选择目标'}
              </div>
              {activeTarget && (
                <div className="mt-0.5 text-xs text-brand-muted">
                  #{activeTarget.id} · {activeTarget.type}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function CustomModePanel() {
  return (
    <div className="card flex h-full flex-col items-center justify-center p-8 text-center">
      <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl bg-brand-primaryLight">
        <svg className="h-8 w-8 text-brand-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 6h9.75M10.5 6a1.5 1.5 0 1 1-3 0m3 0a1.5 1.5 0 1 0-3 0M3.75 6H7.5m3 12h9.75m-9.75 0a1.5 1.5 0 0 1-3 0m3 0a1.5 1.5 0 0 0-3 0m-3.75 0H7.5m9-6h3.75m-3.75 0a1.5 1.5 0 0 1-3 0m3 0a1.5 1.5 0 0 0-3 0m-9.75 0h9.75" />
        </svg>
      </div>
      <h2 className="mb-2 text-xl font-semibold text-brand-text">定制模式</h2>
      <p className="max-w-md text-sm text-brand-secondary">
        面向 Linux / FreeBSD / Nginx 的定制化分析 —— 漏洞发现、验证、利用、修复闭环正在建设中。
      </p>
      <div className="mt-6 inline-flex items-center gap-2 rounded-full bg-brand-bg2 px-3 py-1.5 text-xs text-brand-muted">
        <span className="h-1.5 w-1.5 rounded-full bg-brand-primary animate-pulse" />
        即将上线
      </div>
    </div>
  )
}

