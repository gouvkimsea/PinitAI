import React from 'react';
import { ScanTab } from '../types';
import { FileText, Globe, QrCode, MessageSquare } from 'lucide-react';

interface HeroSectionProps {
  activeTab: ScanTab;
  onSelectTab: (tab: ScanTab) => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({ activeTab, onSelectTab }) => {
  const tabs: { id: ScanTab; label: string; icon: React.ReactNode }[] = [
    { id: 'file', label: 'File', icon: <FileText className="w-4 h-4 mr-2" aria-hidden="true" /> },
    { id: 'url', label: 'URL', icon: <Globe className="w-4 h-4 mr-2" aria-hidden="true" /> },
    { id: 'qr', label: 'QR CODE', icon: <QrCode className="w-4 h-4 mr-2" aria-hidden="true" /> },
    { id: 'message', label: 'MESSAGE', icon: <MessageSquare className="w-4 h-4 mr-2" aria-hidden="true" /> },
  ];

  return (
    <section className="pt-10 pb-4 text-center max-w-4xl mx-auto px-4 sm:px-6">
      {/* Main Headline from the screenshot */}
      <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold text-[#09355e] tracking-tight leading-tight sm:leading-tight">
        Everything you need to check suspicious or suspect in just two clicks.
      </h1>

      {/* Subtitle from the screenshot */}
      <p className="mt-4 sm:mt-5 text-sm sm:text-base md:text-lg text-slate-600 max-w-2xl mx-auto leading-relaxed">
        <span className="font-semibold text-[#0b4d82]">Pinit</span> Analyzes links, messages, QR codes, files, and payment requests for scam signals — giving you a risk score and clear explanation in under 2 seconds.
      </p>

      {/* Tab Navigation matching the screenshot */}
      <div className="mt-8 border-b border-slate-300">
        <div
          role="tablist"
          aria-label="Scan types"
          className="flex justify-center items-center space-x-4 sm:space-x-8 md:space-x-12"
        >
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                role="tab"
                id={`tab-${tab.id}`}
                aria-selected={isActive}
                aria-controls={`panel-${tab.id}`}
                onClick={() => onSelectTab(tab.id)}
                className={`flex items-center pb-3 text-xs sm:text-sm md:text-base font-semibold transition-all relative focus:outline-none focus-visible:ring-2 focus-visible:ring-[#0b4d82] focus-visible:ring-offset-2 rounded-t ${
                  isActive
                    ? 'text-[#0b4d82] font-bold'
                    : 'text-slate-500 hover:text-slate-800'
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
                {isActive && (
                  <span
                    className="absolute bottom-0 left-0 right-0 h-1 bg-[#0b4d82] rounded-t"
                    aria-hidden="true"
                  />
                )}
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
};
