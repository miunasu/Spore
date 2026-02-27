/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        'spore-bg': 'rgb(var(--spore-bg-rgb) / <alpha-value>)',
        'spore-panel': 'rgb(var(--spore-panel-rgb) / <alpha-value>)',
        'spore-card': 'rgb(var(--spore-card-rgb) / <alpha-value>)',
        'spore-accent': 'rgb(var(--spore-accent-rgb) / <alpha-value>)',
        'spore-border': 'rgb(var(--spore-border-rgb) / <alpha-value>)',
        'spore-highlight': 'rgb(var(--spore-highlight-rgb) / <alpha-value>)',
        'spore-highlight-hover': 'rgb(var(--spore-highlight-hover-rgb) / <alpha-value>)',
        'spore-text': 'rgb(var(--spore-text-rgb) / <alpha-value>)',
        'spore-muted': 'rgb(var(--spore-muted-rgb) / <alpha-value>)',
        'spore-error': 'rgb(var(--spore-error-rgb) / <alpha-value>)',
        'spore-warning': 'rgb(var(--spore-warning-rgb) / <alpha-value>)',
        'spore-info': 'rgb(var(--spore-info-rgb) / <alpha-value>)',
        'spore-success': 'rgb(var(--spore-success-rgb) / <alpha-value>)',
      },
      boxShadow: {
        glow: '0 0 20px rgba(16, 163, 127, 0.15)',
        card: '0 2px 8px rgba(0, 0, 0, 0.3)',
        elevated: '0 8px 32px rgba(0, 0, 0, 0.4)',
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
};

