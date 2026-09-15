import React, { useState } from 'react';
import { Menu, X, Lock, Clock, LogOut, User, BookOpen, Activity } from 'lucide-react';
import type { Language } from '../types';
import { translations } from '../i18n/translations';
import type { UserProfile } from '../services/api';

interface HeaderProps {
  lang: Language;
  onLanguageChange: (lang: Language) => void;
  onOpenAuth: () => void;
  onOpenAbout: () => void;
  onOpenHistory: () => void;
  onOpenEducation: () => void;
  onOpenAdmin: () => void;
  onScrollToHowItWorks: () => void;
  user: UserProfile | null;
  onLogout: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  lang,
  onLanguageChange,
  onOpenAuth,
  onOpenAbout,
  onOpenHistory,
  onOpenEducation,
  onOpenAdmin,
  onScrollToHowItWorks,
  user,
  onLogout,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const t = translations[lang];
  const isKm = lang === 'km';

  return (
    <header className="w-full bg-card/90 backdrop-blur-md border-b border-borderDefault sticky top-0 z-40">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        {/* Brand Logo */}
        <a
          href="#"
          className="flex items-center group focus:outline-none focus-visible:ring-2 focus-visible:ring-primary rounded-xl p-0.5"
          aria-label="PinIt Home"
        >
          <img
            src="/logo.png"
            alt="PinIt"
            className="h-9 sm:h-10 w-auto object-contain rounded-lg shadow-xs group-hover:opacity-90 transition-opacity"
          />
        </a>

        {/* Desktop Navigation */}
        <nav className="hidden md:flex items-center gap-6" aria-label="Main Navigation">
          <a
            href="#"
            className="text-xs sm:text-sm font-medium text-typography-body hover:text-primary transition-standard"
          >
            {t.nav.home}
          </a>
          <button
            type="button"
            onClick={onScrollToHowItWorks}
            className="text-xs sm:text-sm font-medium text-typography-muted hover:text-primary transition-standard cursor-pointer"
          >
            {t.nav.howItWorks}
          </button>
          <button
            type="button"
            onClick={onOpenEducation}
            className="text-xs sm:text-sm font-medium text-typography-muted hover:text-primary transition-standard cursor-pointer flex items-center gap-1"
          >
            <BookOpen className="w-3.5 h-3.5 text-primary" />
            <span>{t.nav.education}</span>
          </button>
          <button
            type="button"
            onClick={onOpenAdmin}
            className="text-xs sm:text-sm font-medium text-typography-muted hover:text-primary transition-standard cursor-pointer flex items-center gap-1"
          >
            <Activity className="w-3.5 h-3.5 text-safe" />
            <span>{t.nav.admin}</span>
          </button>
          <button
            type="button"
            onClick={onOpenAbout}
            className="text-xs sm:text-sm font-medium text-typography-muted hover:text-primary transition-standard cursor-pointer"
          >
            {t.nav.about}
          </button>
        </nav>

        {/* Right Controls: Language Switcher & Auth */}
        <div className="hidden md:flex items-center gap-3">
          {/* Language Toggle */}
          <div className="flex items-center bg-surfaceInput p-1 rounded-lg border border-borderDefault">
            <button
              type="button"
              onClick={() => onLanguageChange('en')}
              className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-standard ${
                lang === 'en'
                  ? 'bg-card text-primary shadow-subtle'
                  : 'text-typography-muted hover:text-typography-body'
              }`}
              aria-label="Switch to English"
            >
              EN
            </button>
            <button
              type="button"
              onClick={() => onLanguageChange('km')}
              className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-standard ${
                lang === 'km'
                  ? 'bg-card text-primary shadow-subtle'
                  : 'text-typography-muted hover:text-typography-body'
              }`}
              aria-label="Switch to Khmer"
            >
              ភាសាខ្មែរ
            </button>
          </div>

          {/* User Session or Login */}
          {user ? (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onOpenHistory}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-typography-headline bg-surfaceInput hover:bg-borderDefault border border-borderDefault rounded-lg transition-standard cursor-pointer"
              >
                <Clock className="w-3.5 h-3.5 text-primary" />
                <span>{isKm ? 'ប្រវត្តិវិភាគ' : 'History'}</span>
              </button>

              <div className="flex items-center gap-1.5 text-xs text-typography-muted bg-card px-2.5 py-1.5 rounded-lg border border-borderDefault">
                <User className="w-3.5 h-3.5" />
                <span className="max-w-[120px] truncate font-medium text-typography-headline">{user.email}</span>
                <button
                  type="button"
                  onClick={onLogout}
                  className="p-0.5 hover:text-danger rounded transition-standard ml-1"
                  title={isKm ? 'ចាកចេញ' : 'Logout'}
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ) : (
            <button
              type="button"
              onClick={onOpenAuth}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-typography-body bg-card hover:bg-surfaceInput border border-borderDefault rounded-lg transition-standard cursor-pointer"
            >
              <Lock className="w-3.5 h-3.5 text-typography-muted" />
              <span>{t.nav.loginSignUp}</span>
            </button>
          )}
        </div>

        {/* Mobile menu button */}
        <div className="flex items-center gap-2 md:hidden">
          {/* Mobile Language Switcher */}
          <button
            type="button"
            onClick={() => onLanguageChange(lang === 'en' ? 'km' : 'en')}
            className="p-1.5 rounded-lg border border-borderDefault text-xs font-semibold text-primary bg-surfaceInput"
            aria-label="Toggle language"
          >
            {lang === 'en' ? 'ភាសាខ្មែរ' : 'EN'}
          </button>

          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 text-typography-body hover:text-primary rounded-lg border border-borderDefault bg-card"
            aria-label="Toggle mobile menu"
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-borderDefault bg-card px-4 py-4 space-y-3 shadow-card animate-fadeIn">
          <a
            href="#"
            onClick={() => setMobileMenuOpen(false)}
            className="block text-sm font-medium text-primary py-1.5"
          >
            {t.nav.home}
          </a>
          <button
            type="button"
            onClick={() => {
              setMobileMenuOpen(false);
              onScrollToHowItWorks();
            }}
            className="block w-full text-left text-sm font-medium text-typography-body hover:text-primary py-1.5"
          >
            {t.nav.howItWorks}
          </button>
          <button
            type="button"
            onClick={() => {
              setMobileMenuOpen(false);
              onOpenEducation();
            }}
            className="block w-full text-left text-sm font-medium text-typography-body hover:text-primary py-1.5"
          >
            {t.nav.education}
          </button>
          <button
            type="button"
            onClick={() => {
              setMobileMenuOpen(false);
              onOpenAdmin();
            }}
            className="block w-full text-left text-sm font-medium text-typography-body hover:text-primary py-1.5"
          >
            {t.nav.admin}
          </button>
          <button
            type="button"
            onClick={() => {
              setMobileMenuOpen(false);
              onOpenAbout();
            }}
            className="block w-full text-left text-sm font-medium text-typography-body hover:text-primary py-1.5"
          >
            {t.nav.about}
          </button>
          <div className="pt-2 border-t border-borderDefault space-y-2">
            {user ? (
              <>
                <button
                  type="button"
                  onClick={() => {
                    setMobileMenuOpen(false);
                    onOpenHistory();
                  }}
                  className="w-full py-2 flex items-center justify-center gap-2 text-sm font-medium text-typography-headline bg-surfaceInput hover:bg-borderDefault rounded-lg"
                >
                  <Clock className="w-4 h-4 text-primary" />
                  <span>{isKm ? 'ប្រវត្តិវិភាគ' : 'Scan History'}</span>
                </button>
                <div className="flex items-center justify-between px-2 text-xs text-typography-muted">
                  <span className="truncate">{user.email}</span>
                  <button
                    type="button"
                    onClick={() => {
                      setMobileMenuOpen(false);
                      onLogout();
                    }}
                    className="text-danger flex items-center gap-1 font-medium"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>{isKm ? 'ចាកចេញ' : 'Logout'}</span>
                  </button>
                </div>
              </>
            ) : (
              <button
                type="button"
                onClick={() => {
                  setMobileMenuOpen(false);
                  onOpenAuth();
                }}
                className="w-full py-2 text-center text-sm font-medium text-typography-body bg-surfaceInput hover:bg-borderDefault rounded-lg"
              >
                {t.nav.loginSignUp}
              </button>
            )}
          </div>
        </div>
      )}
    </header>
  );
};
