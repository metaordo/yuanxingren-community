/** Internal role → generic display label to avoid exposing agent architecture.
 *  All 28 entries, indexed by backend role name. */

const WORKER_LABELS: Record<string, string> = {
  'code-auditor':              '代码审计引擎 #1',
  'dataflow-analyst':           '代码审计引擎 #2',
  'crypto-analyst':             '加密分析引擎',
  'auth-analyst':               '认证分析引擎 #1',
  'authn-tester':               '认证分析引擎 #2',
  'dep-analyst':                '依赖分析引擎 #1',
  'supply-chain-analyst':       '依赖分析引擎 #2',
  'config-secrets-scanner':     '配置扫描引擎',
  'protocol-analyst':           '协议分析引擎 #1',
  'state-machine-extractor':    '协议分析引擎 #2',
  'iot-firmware-auditor':       '固件分析引擎 #1',
  'android-analyst':            '固件分析引擎 #2',
  'web-recon':                  'Web 安全引擎 #1',
  'xss-analyst':                'Web 安全引擎 #2',
  'sqli-analyst':               'Web 安全引擎 #3',
  'api-security-analyst':       'Web 安全引擎 #4',
  'business-logic-analyst':     'Web 安全引擎 #5',
  'heap-spray-analyst':         '内存安全引擎 #1',
  'concurrency-analyst':        '内存安全引擎 #2',
  'kernel-driver-analyst':      '内核驱动引擎',
  'ipid-sidechannel-analyst':   '侧信道分析引擎 #1',
  'cross-layer-semantic-analyst':'侧信道分析引擎 #2',
  'nat-conntrack-analyst':      '侧信道分析引擎 #3',
  'bgp-ospf-analyst':           '路由安全引擎 #1',
  'routing-config-analyst':     '路由安全引擎 #2',
  'route-hijack-analyst':       '路由安全引擎 #3',
  'verifier-reviewer':          '质量复核引擎',
  'reporter-writer':            '报告汇总引擎',
}

export function agentLabel(role: string): string {
  return WORKER_LABELS[role] || role
}
