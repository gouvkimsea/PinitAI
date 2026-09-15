import { useState, useEffect } from 'react';
import type { Language } from './types';
import { Header } from './components/Header';
import { HeroSection } from './components/HeroSection';
import { AnalysisCard } from './components/AnalysisCard/AnalysisCard';
import { PrivacyNotice } from './components/PrivacyNotice';
import { PartnerCredits } from './components/PartnerCredits';
import { HowItWorks } from './components/HowItWorks';
import { CommonScams } from './components/CommonScams';
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
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [isAboutOpen, setIsAboutOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [isEducationOpen, setIsEducationOpen] = useState(false);
  const [isAdminOpen, setIsAdminOpen] = useState(false);
  const [user, setUser] = useState<UserProfile | null>(() => api.getCurrentUser());
  const [prefillReportSnippet, setPrefillReportSnippet] = useState('');

  // Apply language dataset attribute to body for Khmer font switching
  useEffect(() => {
    document.body.setAttribute('data-lang', lang);
  }, [lang]);

  const handleOpenReportScam = (snippet?: string) => {
    setPrefillReportSnippet(snippet || '');
    setIsReportOpen(true);
  };

  const handleScrollToHowItWorks = () => {
    const el = document.getElementById('how-it-works-section');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-canvas text-typography-body transition-colors duration-150">
      {/* 1. Header */}
      <Header
        lang={lang}
        onLanguageChange={setLang}
        onOpenAuth={() => setIsAuthOpen(true)}
        onOpenAbout={() => setIsAboutOpen(true)}
        onOpenHistory={() => setIsHistoryOpen(true)}
        onOpenEducation={() => setIsEducationOpen(true)}
        onOpenAdmin={() => setIsAdminOpen(true)}
        onScrollToHowItWorks={handleScrollToHowItWorks}
        user={user}
        onLogout={() => {
          api.logout();
          setUser(null);
        }}
      />

      {/* Main Content Area */}
      <main className="flex-1 pb-16">
        {/* 2. Hero Section */}
        <HeroSection lang={lang} />

        {/* 3. Scam Analysis Utility Card (Primary visual focus) */}
        <section className="px-4" aria-label="Scam Analysis Utility">
          <AnalysisCard
            lang={lang}
            onOpenReportScam={handleOpenReportScam}
          />
        </section>

        {/* 4. Privacy and Trust Statement */}
        <PrivacyNotice lang={lang} />

        {/* 5. Partner / Institution Credits */}
        <PartnerCredits lang={lang} />

        {/* 6. Explanatory & Educational Content */}
        <HowItWorks lang={lang} />
        <CommonScams lang={lang} />
      </main>

      {/* 7. Footer */}
      <Footer
        lang={lang}
        onOpenAbout={() => setIsAboutOpen(true)}
      />

      {/* Interactive Modals */}
      <ReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        prefillSnippet={prefillReportSnippet}
        lang={lang}
      />

      <AuthModal
        isOpen={isAuthOpen}
        onClose={() => setIsAuthOpen(false)}
        lang={lang}
        onSuccess={() => setUser(api.getCurrentUser())}
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
    </div>
  );
}

export default App;
