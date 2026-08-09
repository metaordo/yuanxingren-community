/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          primary: '#e53834',
          primaryHover: '#cc2f2b',
          primaryLight: '#fef2f2',
          primaryBorder: '#fecaca',
          bg: '#ffffff',
          bg2: '#f8f9fb',
          bg3: '#f1f3f5',
          surface: '#ffffff',
          surface2: '#f8f9fb',
          border: '#e5e7eb',
          borderLight: '#f3f4f6',
          text: '#121419',
          secondary: '#4b5563',
          muted: '#9ca3af',
          success: '#059669',
          successLight: '#ecfdf5',
          warning: '#d97706',
          warningLight: '#fffbeb',
          danger: '#dc2626',
          dangerLight: '#fef2f2',
          info: '#2563eb',
          infoLight: '#eff6ff',
        }
      },
      fontFamily: {
        sans: ['"Noto Sans SC"', '"PingFang SC"', '"Microsoft YaHei"', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      boxShadow: {
        'card': '0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)',
        'card-hover': '0 4px 12px rgba(0,0,0,0.08), 0 2px 4px rgba(0,0,0,0.04)',
        'panel': '0 4px 24px rgba(0,0,0,0.06)',
        'nav': '0 1px 0 rgba(0,0,0,0.05)',
        'input-focus': '0 0 0 3px rgba(229, 56, 52, 0.1)',
      },
      borderRadius: {
        '2xl': '1rem',
        '3xl': '1.25rem',
      },
      animation: {
        'fade-in': 'fadein 0.3s ease-out both',
        'slide-up': 'slideup 0.35s cubic-bezier(0.16, 1, 0.3, 1) both',
        'slide-in-right': 'slide-in-right 0.3s cubic-bezier(0.16, 1, 0.3, 1) both',
        'pulse-dot': 'pulsedot 2s ease-in-out infinite',
        'typing': 'typing 1.4s ease-in-out infinite',
      },
      keyframes: {
        fadein: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideup: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'slide-in-right': {
          '0%': { opacity: '0', transform: 'translateX(16px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        pulsedot: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.4' },
        },
        typing: {
          '0%': { opacity: '0.3' },
          '50%': { opacity: '1' },
          '100%': { opacity: '0.3' },
        },
      },
    },
  },
  plugins: [],
}
