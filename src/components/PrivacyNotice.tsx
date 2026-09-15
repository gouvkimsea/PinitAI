import React from 'react';
import { Lock } from 'lucide-react';
import type { Language } from '../types';
import { translations } from '../i18n/translations';

interface PrivacyNoticeProps {
  lang: Language;
}

export const PrivacyNotice: React.FC<PrivacyNoticeProps> = ({ lang }) => {
  const t = translations[lang];

  return (
    <div className="max-w-[672px] mx-auto px-4 mt-6 text-center">
      <div className="inline-flex items-center justify-center gap-2 text-[13px] md:text-sm text-typography-muted font-normal leading-relaxed">
        <Lock className="w-3.5 h-3.5 text-primary flex-shrink-0" />
        <span>
          <strong className="font-semibold text-typography-headline">{t.privacy.title}</strong>{' '}
          {t.privacy.body}
        </span>
      </div>
    </div>
  );
};
