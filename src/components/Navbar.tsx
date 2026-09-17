import React, { useState } from 'react';
import { Menu, X, LogIn, UserPlus, Clock, LogOut, User, Info } from 'lucide-react';
import type { ScanTab, Language } from '../types';
import type { UserProfile } from '../services/api';
import { PinitLogo } from './PinitLogo';

interface NavbarProps {
  activeTab: ScanTab;
  onSelectTab: (tab: ScanTab) => void;
  onOpenAuth: (mode: 'login' | 'signup') => void;
  lang: Language;
  onLanguageChange: (lang: Language) => void;
  user: UserProfile | null;
  onLogout: () => void;
  onOpenHistory: () => void;
  onOpenAbout: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onSelectTab,
  onOpenAuth,
  lang,
  onLanguageChange,
  user,
  onLogout,
  onOpenHistory,
  onOpenAbout,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const isKm = lang === 'km';

  const navItems: { id: ScanTab; label: string; tabTarget: ScanTab }[] = [
    { id: 'file', label: isKm ? 'ស្កេនឯកសារ' : 'SCAN FILE', tabTarget: 'file' },
    { id: 'url', label: isKm ? 'តំណភ្ជាប់/URL' : 'URL/LINK', tabTarget: 'url' },
    { id: 'qr', label: isKm ? 'QR CODE' : 'QR CODE', tabTarget: 'qr' },
    { id: 'message', label: isKm ? 'សារអត្ថបទ' : 'MESSAGE', tabTarget: 'message' },
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
        <div className="relative flex items-center justify-between h-16">
          {/* Logo matching Pinit layout - aligned left */}
          <div className="flex items-center flex-1 justify-start min-w-0">
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

          {/* Desktop Nav Links - Perfectly Centered */}
          <nav
            className="hidden md:flex items-center justify-center space-x-1 lg:space-x-3 md:absolute md:left-1/2 md:-translate-x-1/2"
            aria-label="Main Navigation"
          >
            {navItems.map((item) => {
              const isActive = item.tabTarget && activeTab === item.tabTarget;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.tabTarget)}
                  className={`px-2.5 lg:px-3.5 py-1.5 text-xs lg:text-sm font-semibold tracking-wider rounded-md transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300 ${
                    isActive
                      ? 'bg-sky-500/25 text-white font-bold'
                      : 'text-slate-200 hover:text-white hover:bg-white/10'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Right Action Buttons - aligned right */}
          <div className="hidden md:flex items-center justify-end flex-1 space-x-2.5 lg:space-x-3">
            {/* Language Switcher */}
            <div className="flex items-center bg-sky-950/50 p-0.5 rounded-lg border border-sky-700/50 text-xs">
              <button
                type="button"
                onClick={() => onLanguageChange('en')}
                className={`px-2 py-1 rounded font-bold transition-colors ${
                  lang === 'en'
                    ? 'bg-sky-500 text-white shadow-xs'
                    : 'text-slate-300 hover:text-white'
                }`}
                aria-label="Switch to English"
              >
                EN
              </button>
              <button
                type="button"
                onClick={() => onLanguageChange('km')}
                className={`px-2 py-1 rounded font-bold transition-colors ${
                  lang === 'km'
                    ? 'bg-sky-500 text-white shadow-xs'
                    : 'text-slate-300 hover:text-white'
                }`}
                aria-label="Switch to Khmer"
              >
                ខ្មែរ
              </button>
            </div>

            {/* Authentication / User Session */}
            {user ? (
              <div className="flex items-center space-x-2">
                <button
                  type="button"
                  onClick={onOpenHistory}
                  className="flex items-center space-x-1 px-3 py-1.5 text-xs font-semibold bg-white/10 hover:bg-white/20 text-white rounded-lg border border-white/20 transition-all"
                  title={isKm ? 'ប្រវត្តិវិភាគ' : 'Scan History'}
                >
                  <Clock className="w-3.5 h-3.5 text-sky-300" />
                  <span>{isKm ? 'ប្រវត្តិ' : 'History'}</span>
                </button>

                <div className="flex items-center space-x-1.5 text-xs bg-sky-950/60 px-2.5 py-1.5 rounded-lg border border-sky-700/60">
                  <User className="w-3.5 h-3.5 text-sky-300" />
                  <span className="max-w-[100px] truncate font-medium text-slate-200">{user.email}</span>
                  <button
                    type="button"
                    onClick={onLogout}
                    className="p-0.5 hover:text-rose-400 text-slate-400 rounded transition-colors ml-1"
                    title={isKm ? 'ចាកចេញ' : 'Logout'}
                  >
                    <LogOut className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ) : (
              <>
                <button
                  onClick={() => onOpenAuth('login')}
                  className="px-3.5 py-1.5 text-xs lg:text-sm font-semibold text-slate-200 hover:text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300 rounded-md"
                >
                  {isKm ? 'ចូលប្រើ' : 'Login'}
                </button>
                <button
                  onClick={() => onOpenAuth('signup')}
                  className="px-4 py-1.5 text-xs lg:text-sm font-semibold text-white bg-sky-600 hover:bg-sky-500 active:bg-sky-700 transition-all rounded-full shadow-sm hover:shadow focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-[#0b3e6e] focus-visible:ring-sky-300 border border-sky-400/40"
                >
                  {isKm ? 'ចុះឈ្មោះ' : 'Sign up'}
                </button>
              </>
            )}
          </div>

          {/* Mobile menu button */}
          <div className="flex md:hidden items-center space-x-2">
            {/* Language switcher for mobile */}
            <button
              type="button"
              onClick={() => onLanguageChange(lang === 'en' ? 'km' : 'en')}
              className="px-2 py-1 bg-sky-950/60 border border-sky-700/50 rounded text-xs font-bold text-sky-200"
            >
              {lang === 'en' ? 'ខ្មែរ' : 'EN'}
            </button>

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
            <div className="pt-2 border-t border-sky-800/60 flex flex-col space-y-1">
              <button
                onClick={() => {
                  setMobileMenuOpen(false);
                  onOpenAbout();
                }}
                className="w-full text-left px-3 py-2 text-sm font-semibold rounded-md text-slate-200 hover:text-white hover:bg-white/10 flex items-center space-x-2"
              >
                <Info className="w-4 h-4 text-slate-300" />
                <span>{isKm ? 'អំពី Pinit AI' : 'About Pinit AI'}</span>
              </button>
            </div>
          </nav>

          <div className="pt-3 border-t border-sky-800/80 flex flex-col space-y-2">
            {user ? (
              <>
                <div className="px-3 py-1.5 text-xs text-sky-200 flex items-center justify-between">
                  <span>{user.email}</span>
                  <button
                    onClick={() => {
                      setMobileMenuOpen(false);
                      onLogout();
                    }}
                    className="text-rose-400 hover:underline font-semibold"
                  >
                    {isKm ? 'ចាកចេញ' : 'Logout'}
                  </button>
                </div>
                <button
                  onClick={() => {
                    setMobileMenuOpen(false);
                    onOpenHistory();
                  }}
                  className="w-full flex items-center justify-center space-x-2 px-4 py-2 text-sm font-semibold text-slate-200 hover:text-white bg-white/5 rounded-lg border border-white/10"
                >
                  <Clock className="w-4 h-4 text-sky-300" />
                  <span>{isKm ? 'ប្រវត្តិវិភាគ' : 'Scan History'}</span>
                </button>
              </>
            ) : (
              <>
                <button
                  onClick={() => {
                    setMobileMenuOpen(false);
                    onOpenAuth('login');
                  }}
                  className="w-full flex items-center justify-center space-x-2 px-4 py-2 text-sm font-semibold text-slate-200 hover:text-white bg-white/5 rounded-lg border border-white/10"
                >
                  <LogIn className="w-4 h-4" />
                  <span>{isKm ? 'ចូលប្រើ' : 'Login'}</span>
                </button>
                <button
                  onClick={() => {
                    setMobileMenuOpen(false);
                    onOpenAuth('signup');
                  }}
                  className="w-full flex items-center justify-center space-x-2 px-4 py-2 text-sm font-semibold text-white bg-sky-600 hover:bg-sky-500 rounded-lg shadow-sm"
                >
                  <UserPlus className="w-4 h-4" />
                  <span>{isKm ? 'ចុះឈ្មោះ' : 'Sign up'}</span>
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </header>
  );
};
