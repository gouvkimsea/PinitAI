import React from 'react';
import { PhoneCall } from 'lucide-react';
import type { Language } from '../types';
import { translations } from '../i18n/translations';

interface FooterProps {
  lang: Language;
  onOpenAbout: () => void;
}

export const Footer: React.FC<FooterProps> = ({ lang, onOpenAbout }) => {
  const t = translations[lang];
  const isKm = lang === 'km';

  return (
    <footer className="w-full border-t border-borderDefault bg-card/60 pt-10 pb-8 text-typography-muted">
      <div className="max-w-5xl mx-auto px-4 space-y-8">
        {/* Emergency Fraud Help Callout */}
        <div className="p-4 rounded-xl bg-surfaceInput border border-borderDefault flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-danger-light border border-danger-border flex items-center justify-center text-danger flex-shrink-0">
              <PhoneCall className="w-4 h-4" />
            </div>
            <div>
              <h4 className="text-xs font-bold text-typography-headline">
                {t.footer.emergencyTitle}
              </h4>
              <p className="text-[11px] text-typography-muted mt-0.5">
                {t.footer.emergencyDesc}
              </p>
            </div>
          </div>
          <div className="text-[11px] font-mono font-medium text-slate-700 bg-card px-3 py-1.5 rounded-lg border border-borderDefault flex-shrink-0">
            {isKm ? 'ទូរស័ព្ទទាន់ហេតុការណ៍៖ ១១៧ ឬធនាគារផ្ទាល់' : 'Hotline: FTC 1-877-382-4357'}
          </div>
        </div>

        {/* Footer Navigation and Copyright */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-4 text-xs">
          <div className="flex items-center gap-2.5">
            <img
              src="/logo.png"
              alt="PinIt"
              className="h-6 w-auto object-contain rounded-md shadow-xs"
            />
            <span className="text-slate-400">•</span>
            <span>© {new Date().getFullYear()} {t.footer.rights}</span>
          </div>

          <div className="flex items-center gap-4 text-xs">
            <button
              type="button"
              onClick={onOpenAbout}
              className="hover:text-primary transition-standard cursor-pointer"
            >
              {t.nav.about}
            </button>
            <a href="#" className="hover:text-primary transition-standard">
              {t.footer.privacyPolicy}
            </a>
            <a href="#" className="hover:text-primary transition-standard">
              {t.footer.termsOfService}
            </a>
          </div>
        </div>

        {/* Legal Disclaimer */}
        <p className="text-[11px] text-slate-400 text-center leading-relaxed">
          {t.footer.disclaimer}
        </p>
      </div>
    </footer>
  );
};
