import React, { useState } from 'react';
import { Menu, X, LogIn, UserPlus } from 'lucide-react';
import { ScanTab } from '../types';
import { PinitLogo } from './PinitLogo';

interface NavbarProps {
  activeTab: ScanTab;
  onSelectTab: (tab: ScanTab) => void;
  onOpenAuth: (mode: 'login' | 'signup') => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, onSelectTab, onOpenAuth }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems: { id: ScanTab | 'image'; label: string; tabTarget?: ScanTab }[] = [
    { id: 'file', label: 'SCAN FILE', tabTarget: 'file' },
    { id: 'url', label: 'URL/LINK', tabTarget: 'url' },
    { id: 'qr', label: 'QR CODE', tabTarget: 'qr' },
    { id: 'message', label: 'MESSAGE', tabTarget: 'message' },
    { id: 'image', label: 'IMAGE', tabTarget: 'qr' }, // Image scanner links to visual/QR scan
  ];

  const handleNavClick = (tabTarget?: ScanTab) => {
    if (tabTarget) {
      onSelectTab(tabTarget);
      const scannerEl = document.getElementById('threat-scanner');
      if (scannerEl) {
        scannerEl.scrollIntoView({ behavior: 'smooth' });
      }
    }
    setMobileMenuOpen(false);
  };

  return (
    <header className="sticky top-0 z-40 w-full bg-[#0b3e6e] text-white shadow-md transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo matching uploaded Pinit mark */}
          <div className="flex items-center">
            <button
              onClick={() => {
                window.scrollTo({ top: 0, behavior: 'smooth' });
              }}
              className="flex items-center focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300 rounded-lg p-1 text-white hover:opacity-95 transition-opacity"
              aria-label="Pinit Home"
            >
              <PinitLogo size="md" />
            </button>
          </div>

          {/* Desktop Nav Links */}
          <nav className="hidden md:flex items-center space-x-1 lg:space-x-4" aria-label="Main Navigation">
            {navItems.map((item) => {
              const isActive = item.tabTarget && activeTab === item.tabTarget;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.tabTarget)}
                  className={`px-3 py-1.5 text-xs lg:text-sm font-semibold tracking-wider rounded-md transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300 ${
                    isActive
                      ? 'bg-sky-500/25 text-white font-bold border-b-2 border-sky-400'
                      : 'text-slate-200 hover:text-white hover:bg-white/10'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Right Action Buttons */}
          <div className="hidden md:flex items-center space-x-3">
            <button
              onClick={() => onOpenAuth('login')}
              className="px-3.5 py-1.5 text-xs lg:text-sm font-semibold text-slate-200 hover:text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300 rounded-md"
            >
              Login
            </button>
            <button
              onClick={() => onOpenAuth('signup')}
              className="px-4 py-1.5 text-xs lg:text-sm font-semibold text-white bg-sky-600 hover:bg-sky-500 active:bg-sky-700 transition-all rounded-full shadow-sm hover:shadow focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-[#0b3e6e] focus-visible:ring-sky-300 border border-sky-400/40"
            >
              Sign up
            </button>
          </div>

          {/* Mobile menu button */}
          <div className="flex md:hidden">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              type="button"
              className="p-2 rounded-lg text-slate-200 hover:text-white hover:bg-white/10 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300"
              aria-controls="mobile-menu"
              aria-expanded={mobileMenuOpen}
              aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div id="mobile-menu" className="md:hidden border-t border-sky-800/60 bg-[#093259] px-4 pt-3 pb-5 space-y-3">
          <nav className="flex flex-col space-y-1" aria-label="Mobile Navigation">
            {navItems.map((item) => (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.tabTarget)}
                className="w-full text-left px-3 py-2 text-sm font-semibold rounded-md text-slate-200 hover:text-white hover:bg-white/10 flex items-center justify-between"
              >
                <span>{item.label}</span>
                {item.tabTarget && activeTab === item.tabTarget && (
                  <span className="w-2 h-2 rounded-full bg-sky-400"></span>
                )}
              </button>
            ))}
          </nav>
          <div className="pt-3 border-t border-sky-800/80 flex flex-col space-y-2">
            <button
              onClick={() => {
                setMobileMenuOpen(false);
                onOpenAuth('login');
              }}
              className="w-full flex items-center justify-center space-x-2 px-4 py-2 text-sm font-semibold text-slate-200 hover:text-white bg-white/5 rounded-lg border border-white/10"
            >
              <LogIn className="w-4 h-4" />
              <span>Login</span>
            </button>
            <button
              onClick={() => {
                setMobileMenuOpen(false);
                onOpenAuth('signup');
              }}
              className="w-full flex items-center justify-center space-x-2 px-4 py-2 text-sm font-semibold text-white bg-sky-600 hover:bg-sky-500 rounded-lg shadow-sm"
            >
              <UserPlus className="w-4 h-4" />
              <span>Sign up</span>
            </button>
          </div>
        </div>
      )}
    </header>
  );
};
