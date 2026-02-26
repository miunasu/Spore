/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // 现代深色主题
        'spore-bg': '#0f0f0f',
        'spore-panel': '#1a1a1a',
        'spore-card': '#242424',
        'spore-accent': '#2d2d2d',
        'spore-border': '#3d3d3d',
        'spore-highlight': '#10a37f',
        'spore-highlight-hover': '#1a7f64',
        'spore-text': '#ececec',
        'spore-muted': '#8e8e8e',
        'spore-error': '#ef4444',
        'spore-warning': '#f59e0b',
        'spore-info': '#3b82f6',
        'spore-success': '#10b981',
      },
      boxShadow: {
        'glow': '0 0 20px rgba(16, 163, 127, 0.15)',
        'card': '0 2px 8px rgba(0, 0, 0, 0.3)',
        'elevated': '0 8px 32px rgba(0, 0, 0, 0.4)',
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'pulse-soft': 'pulseSoft 2s infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        pulseSoft: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.7' },
        },
      },
    },
  },
  plugins: [],
}
