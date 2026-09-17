import React from 'react';
import { Lock, Globe2 } from 'lucide-react';
import { PinitLogo } from './PinitLogo';

export const Footer: React.FC = () => {
  return (
    <footer className="w-full bg-[#072440] text-slate-300 pt-12 pb-8 border-t border-slate-800" aria-label="Footer">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 pb-10 border-b border-slate-800/80">
          {/* Brand info with uploaded Pinit Logo */}
          <div className="md:col-span-2 space-y-3">
            <div className="flex items-center text-white">
              <PinitLogo size="md" />
            </div>
            <p className="text-xs text-slate-400 max-w-sm leading-relaxed">
              Every thing you need to check suspicious or suspect files, URLs, QR codes, and messages in just two clicks. Real-time scam signals and risk scores powered by multi-engine threat intelligence.
            </p>
            <div className="flex items-center space-x-3 pt-2 text-[11px] text-slate-400">
              <span className="inline-flex items-center space-x-1 bg-white/5 px-2 py-1 rounded border border-white/10">
                <Lock className="w-3 h-3 text-emerald-400" />
                <span>Zero Log Retention</span>
              </span>
              <span className="inline-flex items-center space-x-1 bg-white/5 px-2 py-1 rounded border border-white/10">
                <Globe2 className="w-3 h-3 text-sky-400" />
                <span>40+ Global Threat Feeds</span>
              </span>
            </div>
          </div>

          {/* Quick links */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100 mb-3">
              Detection Engines
            </h3>
            <ul className="space-y-2 text-xs text-slate-400">
              <li><a href="#threat-scanner" className="hover:text-white transition-colors">File Threat Scanner</a></li>
              <li><a href="#threat-scanner" className="hover:text-white transition-colors">Phishing URL Checker</a></li>
              <li><a href="#threat-scanner" className="hover:text-white transition-colors">QR Code Quishing Analyzer</a></li>
              <li><a href="#threat-scanner" className="hover:text-white transition-colors">SMS & Email Scam Heuristics</a></li>
              <li><a href="#threat-scanner" className="hover:text-white transition-colors">Payment Request Verification</a></li>
            </ul>
          </div>

          {/* Legal & Compliance */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-100 mb-3">
              Trust & Compliance
            </h3>
            <ul className="space-y-2 text-xs text-slate-400">
              <li><span className="hover:text-white cursor-pointer transition-colors">Privacy Policy</span></li>
              <li><span className="hover:text-white cursor-pointer transition-colors">Terms of Protection</span></li>
              <li><span className="hover:text-white cursor-pointer transition-colors">Accessibility Statement (WCAG AA)</span></li>
              <li><span className="hover:text-white cursor-pointer transition-colors">Security Disclosures</span></li>
              <li><a href="#pricing" className="text-sky-400 hover:text-sky-300 font-semibold transition-colors">Upgrade Plan &rarr;</a></li>
            </ul>
          </div>
        </div>

        <div className="pt-6 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-3">
          <p>© {new Date().getFullYear()} Pinit Technologies. All rights reserved.</p>
          <div className="flex items-center space-x-1 text-slate-500">
            <span>Built with focus on responsive layouts and digital safety</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
