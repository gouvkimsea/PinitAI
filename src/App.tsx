import { useState, useEffect } from 'react';
import type { Language, ScanTab } from './types';
import { Navbar } from './components/Navbar';
import { HeroSection } from './components/HeroSection';
import { ThreatScanner } from './components/ThreatScanner';
import { FeatureCards } from './components/FeatureCards';
import { PricingSection } from './components/PricingSection';
import { Footer } from './components/Footer';
import { ReportModal } from './components/Modals/ReportModal';
import { AuthModal } from './components/Modals/AuthModal';
import { AboutModal } from './components/Modals/AboutModal';
import { HistoryModal } from './components/Modals/HistoryModal';
import { EducationModal } from './components/Modals/EducationModal';
import { AdminDashboardModal } from './components/Modals/AdminDashboardModal';
import { api, type UserProfile } from './services/api';

export function App() {
  const [lang, setLang] = useState<Language>('en');
  const [activeTab, setActiveTab] = useState<ScanTab>('file');

  // Modals state
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [authMode, setAuthMode] = useState<'login' | 'signup'>('signup');
  const [selectedPlanForAuth, setSelectedPlanForAuth] = useState<string | null>(null);

  const [isReportOpen, setIsReportOpen] = useState(false);
  const [prefillReportSnippet, setPrefillReportSnippet] = useState('');

  const [isAboutOpen, setIsAboutOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [isEducationOpen, setIsEducationOpen] = useState(false);
  const [isAdminOpen, setIsAdminOpen] = useState(false);

  // User session state
  const [user, setUser] = useState<UserProfile | null>(() => api.getCurrentUser());

  // Listen for session expiration events
  useEffect(() => {
    const handleAuthExpired = () => {
      setUser(null);
    };
    window.addEventListener('pinit:auth-expired', handleAuthExpired);
    return () => window.removeEventListener('pinit:auth-expired', handleAuthExpired);
  }, []);

  // Apply language dataset attribute to body and html for Khmer font switching
  useEffect(() => {
    document.body.setAttribute('data-lang', lang);
    document.documentElement.setAttribute('data-lang', lang);
    document.documentElement.lang = lang;
  }, [lang]);

  // Ensure Elfsight AI Chatbot platform script is loaded and active
  useEffect(() => {
    const scriptSrc = 'https://elfsightcdn.com/platform.js';
    if (!document.querySelector(`script[src*="elfsightcdn.com/platform.js"]`)) {
      const script = document.createElement('script');
      script.src = scriptSrc;
      script.async = true;
      document.body.appendChild(script);
    }
  }, []);

  const handleOpenAuth = (mode: 'login' | 'signup') => {
    setAuthMode(mode);
    setSelectedPlanForAuth(null);
    setIsAuthOpen(true);
  };

  const handleSelectPlan = (planName: string) => {
    setSelectedPlanForAuth(planName);
    setAuthMode('signup');
    setIsAuthOpen(true);
  };

  const handleOpenReportScam = (snippet?: string) => {
    setPrefillReportSnippet(snippet || '');
    setIsReportOpen(true);
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#f5f7fb] text-slate-800 font-sans selection:bg-sky-200 selection:text-sky-900 transition-colors duration-150">
      {/* Accessibility Skip Link */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:px-4 focus:py-2 focus:bg-[#0b3e6e] focus:text-white focus:rounded-md focus:shadow-lg focus:outline-none"
      >
        Skip to main content
      </a>

      {/* Top Navbar matching Figma screenshot */}
      <Navbar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenAuth={handleOpenAuth}
        lang={lang}
        onLanguageChange={setLang}
        user={user}
        onLogout={() => {
          api.logout();
          setUser(null);
        }}
        onOpenHistory={() => setIsHistoryOpen(true)}
        onOpenAbout={() => setIsAboutOpen(true)}
      />

      {/* Main Content Area */}
      <main id="main-content" className="flex-1 w-full pb-16">
        {/* Hero Section with Headline & Tabs */}
        <HeroSection
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          lang={lang}
        />

        {/* Center Scanner & Analysis Area */}
        <ThreatScanner
          activeTab={activeTab}
          onTabChange={setActiveTab}
          lang={lang}
          onOpenReportScam={handleOpenReportScam}
        />

        {/* 4 Feature/Capability Cards */}
        <FeatureCards
          onSelectTab={setActiveTab}
        />

        {/* UPGRADE YOUR PLAN Section with 3 Pricing Cards */}
        <PricingSection
          onSelectPlan={handleSelectPlan}
        />
      </main>

      {/* Footer */}
      <Footer
        lang={lang}
        onOpenAbout={() => setIsAboutOpen(true)}
        onOpenAdmin={() => setIsAdminOpen(true)}
        onOpenEducation={() => setIsEducationOpen(true)}
      />

      {/* Interactive Modals */}
      <AuthModal
        isOpen={isAuthOpen}
        initialMode={authMode}
        planName={selectedPlanForAuth}
        onClose={() => setIsAuthOpen(false)}
        lang={lang}
        onSuccess={() => {
          setUser(api.getCurrentUser());
        }}
      />

      <ReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        prefillSnippet={prefillReportSnippet}
        lang={lang}
      />

      <AboutModal
        isOpen={isAboutOpen}
        onClose={() => setIsAboutOpen(false)}
        lang={lang}
      />

      <HistoryModal
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        lang={lang}
      />

      <EducationModal
        isOpen={isEducationOpen}
        onClose={() => setIsEducationOpen(false)}
        lang={lang}
      />

      <AdminDashboardModal
        isOpen={isAdminOpen}
        onClose={() => setIsAdminOpen(false)}
        lang={lang}
      />

      {/* Elfsight AI Chatbot | PinitAI Chatbot Floating Launcher */}
      <div className="elfsight-app-7a5f92e9-c085-42cb-a813-0f57c279707c" />
    </div>
  );
}

export default App;
