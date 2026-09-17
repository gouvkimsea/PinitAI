import React from 'react';
import type { Language, ScanTab } from '../types';
import type { AboutModalTab } from './Modals/AboutModal';
import { PinitLogo } from './PinitLogo';

interface FooterProps {
  lang?: Language;
  onSelectTab?: (tab: ScanTab) => void;
  onOpenAbout?: (initialTab?: AboutModalTab) => void;
  onOpenAdmin?: () => void;
  onOpenEducation?: () => void;
}

export const Footer: React.FC<FooterProps> = ({
  lang = 'en',
  onSelectTab,
  onOpenAbout,
  onOpenAdmin,
  onOpenEducation,
}) => {
  const isKm = lang === 'km';

  const handleEngineClick = (tab: ScanTab) => {
    onSelectTab?.(tab);
    const el = document.getElementById('threat-scanner');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleScrollToPricing = (e: React.MouseEvent) => {
    e.preventDefault();
    const el = document.getElementById('pricing');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <footer className="w-full bg-[#072440] text-slate-300 pt-12 pb-8 border-t border-slate-800" aria-label="Footer">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 space-y-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 pb-10 border-b border-slate-800/80">
          {/* Brand info with Pinit Logo */}
          <div className="md:col-span-2 space-y-3">
            <div className="flex items-center text-white">
              <PinitLogo size="md" />
            </div>
            <p className="text-xs text-slate-400 max-w-sm leading-relaxed">
              {isKm
                ? 'គ្រប់យ៉ាងដែលអ្នកត្រូវការ ដើម្បីពិនិត្យមើលឯកសារ តំណភ្ជាប់ កូដ QR និងសារដែលគួរឱ្យសង្ស័យ ត្រឹមតែពីរជំហានប៉ុណ្ណោះ។ ដំណើរការដោយប្រព័ន្ធឆ្លាតវៃ AI និងទិន្នន័យព្រមានសកល។'
                : 'Everything you need to check suspicious or suspect files, URLs, QR codes, and messages in just two clicks. Real-time scam signals and risk scores powered by multi-engine threat intelligence.'}
            </p>
          </div>

          {/* Quick links to detection engines */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100 mb-3">
              Detection Engines
            </h3>
            <ul className="space-y-2 text-xs text-slate-400">
              <li>
                <button
                  type="button"
                  onClick={() => handleEngineClick('file')}
                  className="hover:text-white transition-colors cursor-pointer text-left"
                >
                  File Threat Scanner
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={() => handleEngineClick('url')}
                  className="hover:text-white transition-colors cursor-pointer text-left"
                >
                  Phishing URL Checker
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={() => handleEngineClick('qr')}
                  className="hover:text-white transition-colors cursor-pointer text-left"
                >
                  QR Code Quishing Analyzer
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={() => handleEngineClick('message')}
                  className="hover:text-white transition-colors cursor-pointer text-left"
                >
                  SMS & Email Scam Heuristics
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={() => handleEngineClick('message')}
                  className="hover:text-white transition-colors cursor-pointer text-left"
                >
                  Payment Request Verification
                </button>
              </li>
            </ul>
          </div>

          {/* Trust & Compliance */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100 mb-3">
              Trust & Compliance
            </h3>
            <ul className="space-y-2 text-xs text-slate-400">
              <li>
                <button
                  type="button"
                  onClick={() => onOpenAbout?.('about')}
                  className="hover:text-white cursor-pointer transition-colors text-left"
                >
                  {isKm ? 'អំពី Pinit AI' : 'About Pinit AI'}
                </button>
              </li>
              {onOpenEducation && (
                <li>
                  <button
                    type="button"
                    onClick={onOpenEducation}
                    className="hover:text-white cursor-pointer transition-colors text-left"
                  >
                    {isKm ? 'ការអប់រំសុវត្ថិភាពសន្តិសុខ' : 'Cybersecurity Education'}
                  </button>
                </li>
              )}
              <li>
                <button
                  type="button"
                  onClick={() => onOpenAbout?.('privacy')}
                  className="hover:text-white cursor-pointer transition-colors text-left"
                >
                  Privacy Policy & Zero-Retention
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={() => onOpenAbout?.('terms')}
                  className="hover:text-white cursor-pointer transition-colors text-left"
                >
                  Terms of Protection
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={onOpenAdmin}
                  className="hover:text-white cursor-pointer transition-colors text-left"
                >
                  {isKm ? 'ផ្ទាំងគ្រប់គ្រង Admin' : 'Admin Operations & Telemetry'}
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={() => onOpenAbout?.('accessibility')}
                  className="hover:text-white cursor-pointer transition-colors text-left"
                >
                  Accessibility Statement (WCAG AA)
                </button>
              </li>
              <li>
                <a
                  href="#pricing"
                  onClick={handleScrollToPricing}
                  className="text-sky-400 hover:text-sky-300 font-semibold transition-colors inline-block"
                >
                  Upgrade Plan &rarr;
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="pt-6 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-3">
          <p>© {new Date().getFullYear()} Pinit Technologies. All rights reserved.</p>
          <div className="flex items-center space-x-1 text-slate-500">
            <span>Built with focus on responsive layouts, bilingual safety, and digital protection</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
