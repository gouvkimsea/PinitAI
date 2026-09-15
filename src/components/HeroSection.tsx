import React from 'react';
import type { Language } from '../types';
import { translations } from '../i18n/translations';

interface HeroSectionProps {
  lang: Language;
}

export const HeroSection: React.FC<HeroSectionProps> = ({ lang }) => {
  const t = translations[lang];

  return (
    <section className="pt-16 pb-8 md:pt-16 md:pb-10 max-w-[720px] mx-auto px-4 text-center">

      {/* Main question-led headline */}
      <h1 className="text-3xl sm:text-4xl md:text-[40px] md:leading-[48px] font-bold text-typography-headline tracking-tight mb-4">
        {t.hero.headline}
      </h1>

      {/* Subheadline */}
      <p className="text-base leading-6 text-typography-muted max-w-[600px] mx-auto font-normal">
        {t.hero.subheadline}
      </p>
    </section>
  );
};
