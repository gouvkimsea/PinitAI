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
          DEFAULT: '#0b4d82',
          hover: '#093c66',
          focus: '#0284c7',
          soft: '#e0f2fe',
          dark: '#072440',
        },
        typography: {
          headline: '#0F172A',
          altHeadline: '#1E293B',
          body: '#334155',
          muted: '#64748B',
        },
        borderDefault: '#E2E8F0',
        borderFocus: '#0b4d82',
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
        warning: {
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
        sans: ['Plus Jakarta Sans', 'Inter', '"!Khmer OS Siemreap"', '"Khmer OS Siemreap"', 'Siemreap', 'system-ui', '-apple-system', 'sans-serif'],
        display: ['Space Grotesk', 'Plus Jakarta Sans', '"!Khmer OS Siemreap"', '"Khmer OS Siemreap"', 'Siemreap', 'sans-serif'],
        khmer: ['"!Khmer OS Siemreap"', '"Khmer OS Siemreap"', 'Siemreap', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        'xs': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        'subtle': '0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px 0 rgba(0, 0, 0, 0.03)',
        'card': '0 4px 6px -1px rgba(0, 0, 0, 0.04), 0 2px 4px -1px rgba(0, 0, 0, 0.02)',
        'elevated': '0 10px 25px -3px rgba(0, 0, 0, 0.05), 0 4px 6px -2px rgba(0, 0, 0, 0.02)',
      }
    },
  },
  plugins: [],
}
