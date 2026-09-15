/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        canvas: '#FFFFFF',
        card: '#FFFFFF',
        surfaceInput: '#F1F5F9',
        primary: {
          DEFAULT: '#1A877E', // rgb(26, 135, 126)
          hover: '#126B64',   // rgb(18, 107, 100)
          focus: '#22A398',
          soft: '#E6F6F5',
          dark: '#0E5650',
        },
        typography: {
          headline: '#0F172A',
          altHeadline: '#1E293B',
          body: '#334155',
          muted: '#64748B',
        },
        borderDefault: '#E2E8F0',
        borderFocus: '#1A877E',
        safe: {
          light: '#ECFDF5',
          DEFAULT: '#10B981',
          border: '#A7F3D0',
          dark: '#065F46',
        },
        suspicious: {
          light: '#FFFBEB',
          DEFAULT: '#F59E0B',
          border: '#FDE68A',
          dark: '#92400E',
        },
        danger: {
          light: '#FEF2F2',
          DEFAULT: '#EF4444',
          border: '#FECACA',
          dark: '#991B1B',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        khmer: ['Kantumruy Pro', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'subtle': '0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px 0 rgba(0, 0, 0, 0.03)',
        'card': '0 4px 6px -1px rgba(0, 0, 0, 0.04), 0 2px 4px -1px rgba(0, 0, 0, 0.02)',
        'elevated': '0 10px 25px -3px rgba(0, 0, 0, 0.05), 0 4px 6px -2px rgba(0, 0, 0, 0.02)',
      }
    },
  },
  plugins: [],
}
