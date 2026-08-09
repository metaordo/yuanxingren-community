import React from 'react'

type Props = {
  size?: number
  className?: string
  /** 'solid' = 红底白刃； 'outline' = 玄色盾牌 + 红刃 */
  variant?: 'solid' | 'outline'
  /** 大尺寸 hero 时启用：盾内电路/节点/锁定十字 */
  detail?: boolean
}

export default function BrandMark({ size = 32, className = '', variant = 'outline', detail = false }: Props) {
  const isSolid = variant === 'solid'
  const shieldFill = isSolid ? '#e53834' : '#0f1115'
  const shieldStroke = isSolid ? 'none' : '#e53834'
  const bladeFill = isSolid ? '#ffffff' : '#e53834'
  const bladeHi = isSolid ? '#ffd5d4' : '#ff6b6b'
  const accent = isSolid ? '#ffffff' : '#e53834'

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 32 32"
      width={size}
      height={size}
      className={className}
      aria-label="元星刃"
    >
      <path
        d="M16 2 L28 5.5 V15 C28 21.5 22.5 27 16 30 C9.5 27 4 21.5 4 15 V5.5 Z"
        fill={shieldFill}
        stroke={shieldStroke}
        strokeWidth={1}
        strokeLinejoin="round"
      />

      {detail && (
        <g stroke={accent} fill={accent} strokeLinecap="round" strokeLinejoin="round">
          {/* 左侧电路走线 + 节点 */}
          <g opacity={0.55} strokeWidth={0.35}>
            <path d="M7 9 L7 12 L9.5 12 L9.5 16 L7 16 L7 19.5" fill="none" />
            <circle cx="7" cy="9" r="0.7" stroke="none" />
            <circle cx="9.5" cy="12" r="0.7" stroke="none" />
            <circle cx="9.5" cy="16" r="0.7" stroke="none" />
            <circle cx="7" cy="19.5" r="0.7" stroke="none" />
          </g>
          {/* 右侧镜像电路走线 + 节点 */}
          <g opacity={0.55} strokeWidth={0.35}>
            <path d="M25 9 L25 12 L22.5 12 L22.5 16 L25 16 L25 19.5" fill="none" />
            <circle cx="25" cy="9" r="0.7" stroke="none" />
            <circle cx="22.5" cy="12" r="0.7" stroke="none" />
            <circle cx="22.5" cy="16" r="0.7" stroke="none" />
            <circle cx="25" cy="19.5" r="0.7" stroke="none" />
          </g>
          {/* 顶部锁定十字（侦察/扫描） */}
          <g opacity={0.7} strokeWidth={0.45} fill="none">
            <circle cx="16" cy="5" r="0.9" />
            <path d="M16 3.5 L16 4.3 M16 5.7 L16 6.5 M14.5 5 L15.3 5 M16.7 5 L17.5 5" />
          </g>
          {/* 底部数据扫描线（短刻度） */}
          <g opacity={0.45} strokeWidth={0.35}>
            <path d="M11 27 L12 27 M13.5 27.5 L14.5 27.5 M17.5 27.5 L18.5 27.5 M20 27 L21 27" fill="none" />
          </g>
        </g>
      )}

      {/* 中央红刃 */}
      <path d="M16 6.5 L17.6 16 L16 25.5 L14.4 16 Z" fill={bladeFill} />
      <path d="M16 6.5 L15.6 16 L16 25.5 L14.4 16 Z" fill={bladeHi} opacity={0.55} />
    </svg>
  )
}

