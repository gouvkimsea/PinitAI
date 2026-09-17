/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Navbar } from './components/Navbar';
import { HeroSection } from './components/HeroSection';
import { ThreatScanner } from './components/ThreatScanner';
import { FeatureCards } from './components/FeatureCards';
import { PricingSection } from './components/PricingSection';
import { Footer } from './components/Footer';
import { AuthModal } from './components/AuthModal';
import { ScanTab } from './types';

export default function App() {
  const [activeTab, setActiveTab] = useState<ScanTab>('file');
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authMode, setAuthMode] = useState<'login' | 'signup'>('signup');
  const [selectedPlanForAuth, setSelectedPlanForAuth] = useState<string | null>(null);

  const handleOpenAuth = (mode: 'login' | 'signup') => {
    setAuthMode(mode);
    setSelectedPlanForAuth(null);
    setAuthModalOpen(true);
  };

  const handleSelectPlan = (planName: string) => {
    setSelectedPlanForAuth(planName);
    setAuthMode('signup');
    setAuthModalOpen(true);
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#f5f7fb] text-slate-800 font-sans selection:bg-sky-200 selection:text-sky-900">
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
      />

      {/* Main Content Area */}
      <main id="main-content" className="flex-1 w-full">
        {/* Hero Section with Headline & Tabs */}
        <HeroSection
          activeTab={activeTab}
          onSelectTab={setActiveTab}
        />

        {/* Center Scanner & Analysis Area */}
        <ThreatScanner
          activeTab={activeTab}
          onTabChange={setActiveTab}
        />

        {/* 4 Feature/Capability Cards from Figma Screenshot */}
        <FeatureCards
          onSelectTab={setActiveTab}
        />

        {/* UPGRADE YOUR PLAN Section with 3 Pricing Cards */}
        <PricingSection
          onSelectPlan={handleSelectPlan}
        />
      </main>

      {/* Footer */}
      <Footer />

      {/* Authentication & Subscription Modal */}
      <AuthModal
        isOpen={authModalOpen}
        initialMode={authMode}
        planName={selectedPlanForAuth}
        onClose={() => setAuthModalOpen(false)}
      />
    </div>
  );
}
