import { useState, useEffect } from 'react';
import type { Language, ScanTab, AnalysisResult, RiskLevel } from './types';
import { Navbar } from './components/Navbar';
import { HeroSection } from './components/HeroSection';
import { ThreatScanner } from './components/ThreatScanner';
import { FeatureCards } from './components/FeatureCards';
import { PricingSection } from './components/PricingSection';
import { Footer } from './components/Footer';
import { ReportModal } from './components/Modals/ReportModal';
import { AuthModal } from './components/Modals/AuthModal';
import { AboutModal, type AboutModalTab } from './components/Modals/AboutModal';
import { HistoryModal } from './components/Modals/HistoryModal';
import { EducationModal } from './components/Modals/EducationModal';
import { AdminDashboardModal } from './components/Modals/AdminDashboardModal';
import { api, type UserProfile, type ScanHistoryItem } from './services/api';

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
  const [aboutInitialTab, setAboutInitialTab] = useState<AboutModalTab>('about');

  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [isEducationOpen, setIsEducationOpen] = useState(false);
  const [isAdminOpen, setIsAdminOpen] = useState(false);

  // Scanner prefill and loaded result
  const [prefilledScanTarget, setPrefilledScanTarget] = useState('');
  const [loadedScanResult, setLoadedScanResult] = useState<AnalysisResult | null>(null);

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

  const handleOpenAbout = (tab: AboutModalTab = 'about') => {
    setAboutInitialTab(tab);
    setIsAboutOpen(true);
  };

  const handleSelectScanTab = (tab: ScanTab) => {
    setActiveTab(tab);
    setLoadedScanResult(null);
    const scannerEl = document.getElementById('threat-scanner');
    if (scannerEl) {
      scannerEl.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleTestScam = (tab: ScanTab, sample: string) => {
    setActiveTab(tab);
    setPrefilledScanTarget(sample);
    setLoadedScanResult(null);
    const scannerEl = document.getElementById('threat-scanner');
    if (scannerEl) {
      scannerEl.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleSelectScanHistory = (scan: ScanHistoryItem) => {
    const targetTab: ScanTab = scan.type === 'FILE' ? 'file' : 'url';
    setActiveTab(targetTab);
    setPrefilledScanTarget(scan.target);

    const norm = (scan.threat_level || 'SAFE').toUpperCase();
    const rLevel: RiskLevel =
      norm === 'MALICIOUS' || norm === 'HIGH_RISK'
        ? 'high_risk'
        : norm === 'SUSPICIOUS'
        ? 'suspicious'
        : 'safe';

    const mappedResult: AnalysisResult = {
      id: scan.id,
      timestamp: new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      mode: scan.type === 'FILE' ? 'file' : 'url',
      inputSnippet: scan.target,
      riskLevel: rLevel,
      riskScore: scan.risk_score,
      title: rLevel === 'high_risk' ? 'High Risk Threat Detected' : rLevel === 'suspicious' ? 'Suspicious Indicators Flagged' : 'Likely Safe — Clean Target',
      summary: `Archived scan record evaluated with score ${scan.risk_score}/100 and ${scan.detection_count} engine detections.`,
      signals: scan.detection_count > 0 ? [{
        id: `sig-${scan.id}`,
        category: 'general',
        title: 'Recorded Threat Signature',
        description: `Target matched ${scan.detection_count} threat intelligence patterns.`,
        severity: rLevel === 'high_risk' ? 'high' : 'medium',
      }] : [],
      recommendedActions: rLevel === 'high_risk'
        ? ['Do not open, download, or execute this target.', 'Block sender or isolate infected device.']
        : ['Target passed security checks. Practice standard security hygiene.'],
      confidenceScore: 90,
      details: {
        indicatorsFound: scan.detection_count,
        safeFactors: scan.detection_count === 0 ? ['Verified safe in platform history database'] : [],
        domainEvaluated: scan.details?.domain || (scan.type === 'URL' ? scan.target : undefined),
        fileName: scan.details?.file_name || (scan.type === 'FILE' ? scan.target : undefined),
      },
    };

    setLoadedScanResult(mappedResult);
    const scannerEl = document.getElementById('threat-scanner');
    if (scannerEl) {
      scannerEl.scrollIntoView({ behavior: 'smooth' });
    }
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

      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        onSelectTab={handleSelectScanTab}
        onOpenAuth={handleOpenAuth}
        lang={lang}
        onLanguageChange={setLang}
        user={user}
        onLogout={() => {
          api.logout();
          setUser(null);
        }}
        onOpenHistory={() => setIsHistoryOpen(true)}
        onOpenAbout={() => handleOpenAbout('about')}
      />

      {/* Main Content Area */}
      <main id="main-content" className="flex-1 w-full pb-16">
        {/* Hero Section with Headline & Tabs */}
        <HeroSection
          activeTab={activeTab}
          onSelectTab={handleSelectScanTab}
          lang={lang}
        />

        {/* Center Scanner & Analysis Area */}
        <ThreatScanner
          activeTab={activeTab}
          onTabChange={handleSelectScanTab}
          lang={lang}
          onOpenReportScam={handleOpenReportScam}
          prefilledTarget={prefilledScanTarget}
          loadedResult={loadedScanResult}
        />

        {/* 4 Feature/Capability Cards */}
        <FeatureCards
          onSelectTab={handleSelectScanTab}
        />

        {/* UPGRADE YOUR PLAN Section with 3 Pricing Cards */}
        <PricingSection
          onSelectPlan={handleSelectPlan}
        />
      </main>

      {/* Footer */}
      <Footer
        lang={lang}
        onSelectTab={handleSelectScanTab}
        onOpenAbout={handleOpenAbout}
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
        initialTab={aboutInitialTab}
        onClose={() => setIsAboutOpen(false)}
        lang={lang}
      />

      <HistoryModal
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        lang={lang}
        onSelectScan={handleSelectScanHistory}
      />

      <EducationModal
        isOpen={isEducationOpen}
        onClose={() => setIsEducationOpen(false)}
        lang={lang}
        onTestScam={handleTestScam}
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
