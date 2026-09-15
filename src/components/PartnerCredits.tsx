import React from 'react';
import { Shield, Building2, Globe } from 'lucide-react';
import type { Language } from '../types';
import { translations } from '../i18n/translations';

interface PartnerCreditsProps {
  lang: Language;
}

export const PartnerCredits: React.FC<PartnerCreditsProps> = ({ lang }) => {
  const t = translations[lang];

  return (
    <div className="max-w-[720px] mx-auto px-4 mt-12 mb-8 text-center border-t border-borderDefault/60 pt-6">
      <p className="text-[12px] md:text-[13px] text-slate-400 font-medium mb-3">
        {t.partners.label}
      </p>
      <div className="flex flex-wrap items-center justify-center gap-4 sm:gap-8 text-slate-400 text-xs">
        <div className="flex items-center gap-1.5 hover:text-slate-600 transition-standard">
          <Globe className="w-3.5 h-3.5" />
          <span>{t.partners.alliance}</span>
        </div>
        <div className="flex items-center gap-1.5 hover:text-slate-600 transition-standard">
          <Shield className="w-3.5 h-3.5" />
          <span>{t.partners.apwg}</span>
        </div>
        <div className="flex items-center gap-1.5 hover:text-slate-600 transition-standard">
          <Building2 className="w-3.5 h-3.5" />
          <span>{t.partners.cisa}</span>
        </div>
      </div>
    </div>
  );
};
