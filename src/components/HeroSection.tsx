import React from 'react';
import type { ScanTab, Language } from '../types';
import { FileText, Globe, QrCode, MessageSquare } from 'lucide-react';

interface HeroSectionProps {
  activeTab: ScanTab;
  onSelectTab: (tab: ScanTab) => void;
  lang?: Language;
}

export const HeroSection: React.FC<HeroSectionProps> = ({ activeTab, onSelectTab, lang = 'en' }) => {
  const isKm = lang === 'km';

  const tabs: { id: ScanTab; label: string; icon: React.ReactNode }[] = [
    { id: 'file', label: isKm ? 'ឯកសារ' : 'File', icon: <FileText className="w-4 h-4 mr-2" aria-hidden="true" /> },
    { id: 'url', label: 'URL', icon: <Globe className="w-4 h-4 mr-2" aria-hidden="true" /> },
    { id: 'qr', label: 'QR CODE', icon: <QrCode className="w-4 h-4 mr-2" aria-hidden="true" /> },
    { id: 'message', label: isKm ? 'សារអត្ថបទ' : 'MESSAGE', icon: <MessageSquare className="w-4 h-4 mr-2" aria-hidden="true" /> },
  ];

  return (
    <section className="pt-10 pb-4 text-center max-w-4xl mx-auto px-4 sm:px-6">
      {/* Main Headline with clear gap between sentences and clean Khmer typography */}
      <h1
        className={`text-3xl sm:text-4xl md:text-5xl font-extrabold text-[#09355e] ${
          isKm ? 'leading-[1.85] tracking-normal' : 'tracking-tight leading-snug sm:leading-tight'
        }`}
      >
        {isKm ? (
          <div className="flex flex-col items-center gap-3 sm:gap-4">
            <span className="block leading-[1.85] sm:leading-[1.95]">
              គ្រប់យ៉ាងដែលអ្នកត្រូវការ ដើម្បីពិនិត្យមើល
            </span>
            <span className="block leading-[1.85] sm:leading-[1.95]">
              ភាពគួរឱ្យសង្ស័យ ត្រឹមតែពីរជំហានប៉ុណ្ណោះ។
            </span>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2 sm:gap-2.5">
            <span className="block leading-snug sm:leading-tight">
              Everything you need to check suspicious or suspect
            </span>
            <span className="block leading-snug sm:leading-tight text-[#0b4d82]">
              in just two clicks.
            </span>
          </div>
        )}
      </h1>

      {/* Subtitle with generous line spacing */}
      <p className={`mt-5 sm:mt-6 text-sm sm:text-base md:text-lg text-slate-600 max-w-2xl mx-auto ${isKm ? 'leading-[1.9]' : 'leading-relaxed'}`}>
        <span className="font-semibold text-[#0b4d82]">Pinit</span>{' '}
        {isKm
          ? 'វិភាគតំណភ្ជាប់ សារ SMS/Telegram កូដ QR ឯកសារ និងសំណើទូទាត់ប្រាក់ ដើម្បីស្វែងរកសញ្ញាឆបោក — ផ្តល់ពិន្ទុហានិភ័យ និងការពន្យល់យ៉ាងច្បាស់លាស់ក្នុងពេលមិនដល់ ២ វិនាទី។'
          : 'Analyzes links, messages, QR codes, files, and payment requests for scam signals — giving you a risk score and clear explanation in under 2 seconds.'}
      </p>

      {/* Tab Navigation matching the screenshot */}
      <div className="mt-8 border-b border-slate-300">
        <div
          role="tablist"
          aria-label="Scan types"
          className="flex justify-center items-center space-x-2.5 sm:space-x-8 md:space-x-12 overflow-x-auto pb-0.5"
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
                className={`flex items-center pb-3 text-xs sm:text-sm md:text-base font-semibold transition-all relative shrink-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#0b4d82] focus-visible:ring-offset-2 rounded-t ${
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
