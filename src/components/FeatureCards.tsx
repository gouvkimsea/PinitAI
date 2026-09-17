import React from 'react';
import { FileText, Link2, QrCode, MessageSquare, ArrowUpRight } from 'lucide-react';
import type { ScanTab } from '../types';

interface FeatureCardsProps {
  onSelectTab: (tab: ScanTab) => void;
}

export const FeatureCards: React.FC<FeatureCardsProps> = ({ onSelectTab }) => {
  const cards = [
    {
      id: 'file' as ScanTab,
      title: 'SCAN FILE',
      icon: (
        <div className="w-10 h-10 rounded-lg bg-sky-50 text-[#0b4d82] flex items-center justify-center mx-auto mb-3">
          <FileText className="w-6 h-6 stroke-[2]" aria-hidden="true" />
        </div>
      ),
      description:
        'Upload files to detect malicious extensions, macro viruses, ransomware signatures, and exploit payloads.',
    },
    {
      id: 'url' as ScanTab,
      title: 'URL/LINK',
      icon: (
        <div className="w-10 h-10 rounded-lg bg-sky-50 text-[#0b4d82] flex items-center justify-center mx-auto mb-3">
          <Link2 className="w-6 h-6 stroke-[2]" aria-hidden="true" />
        </div>
      ),
      description:
        'Instantly checks URLs for phishing, spoofing, and malicious redirects against 40+ threat databases.',
    },
    {
      id: 'qr' as ScanTab,
      title: 'QR CODE',
      icon: (
        <div className="w-10 h-10 rounded-lg bg-sky-50 text-[#0b4d82] flex items-center justify-center mx-auto mb-3">
          <QrCode className="w-6 h-6 stroke-[2]" aria-hidden="true" />
        </div>
      ),
      description:
        'Upload QR code images — Pinit decodes and analyzes the hidden destination before you scan it.',
    },
    {
      id: 'message' as ScanTab,
      title: 'MESSAGE',
      icon: (
        <div className="w-10 h-10 rounded-lg bg-sky-50 text-[#0b4d82] flex items-center justify-center mx-auto mb-3">
          <MessageSquare className="w-6 h-6 stroke-[2]" aria-hidden="true" />
        </div>
      ),
      description:
        'Analyze suspicious emails, SMS messages, and social DMs for social engineering scams and urgent payment tricks.',
    },
  ];

  const handleCardClick = (tab: ScanTab) => {
    onSelectTab(tab);
    const scannerEl = document.getElementById('threat-scanner');
    if (scannerEl) {
      scannerEl.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent, tab: ScanTab) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleCardClick(tab);
    }
  };

  return (
    <section className="max-w-6xl mx-auto px-4 sm:px-6 py-8" aria-label="Core Protection Capabilities">
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 sm:gap-5 lg:gap-6">
        {cards.map((card) => (
          <article
            key={card.id}
            role="button"
            tabIndex={0}
            aria-label={`Open ${card.title} scanner`}
            onClick={() => handleCardClick(card.id)}
            onKeyDown={(e) => handleKeyDown(e, card.id)}
            className="group relative bg-white rounded-2xl border border-slate-300/80 p-5 sm:p-6 text-center shadow-xs hover:shadow-md hover:border-[#0b4d82] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#0b4d82] focus-visible:ring-offset-2 transition-all duration-200 cursor-pointer flex flex-col items-center justify-between h-full"
          >
            <div className="w-full">
              {card.icon}
              <h2 className="text-xs sm:text-sm font-bold tracking-wider text-[#0b4d82] uppercase mb-2">
                {card.title}
              </h2>
              <p className="text-xs text-slate-600 leading-relaxed max-w-xs mx-auto">
                {card.description}
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-100 w-full flex items-center justify-center text-xs font-semibold text-[#0b4d82] opacity-80 group-hover:opacity-100 transition-opacity">
              <span>Open Scanner</span>
              <ArrowUpRight className="w-3.5 h-3.5 ml-1 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
            </div>
          </article>
        ))}
      </div>
    </section>
  );
};
