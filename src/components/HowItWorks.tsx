import React from 'react';
import { UploadCloud, Cpu, ShieldCheck } from 'lucide-react';
import type { Language } from '../types';
import { translations } from '../i18n/translations';

interface HowItWorksProps {
  lang: Language;
}

export const HowItWorks: React.FC<HowItWorksProps> = ({ lang }) => {
  const t = translations[lang];

  const steps = [
    {
      icon: <UploadCloud className="w-6 h-6 text-primary" />,
      title: t.howItWorks.step1Title,
      desc: t.howItWorks.step1Desc,
    },
    {
      icon: <Cpu className="w-6 h-6 text-primary" />,
      title: t.howItWorks.step2Title,
      desc: t.howItWorks.step2Desc,
    },
    {
      icon: <ShieldCheck className="w-6 h-6 text-safe" />,
      title: t.howItWorks.step3Title,
      desc: t.howItWorks.step3Desc,
    },
  ];

  return (
    <section id="how-it-works-section" className="py-14 max-w-5xl mx-auto px-4 border-t border-borderDefault">
      <div className="text-center max-w-xl mx-auto mb-10">
        <h2 className="text-2xl sm:text-3xl font-bold text-typography-headline tracking-tight mb-2">
          {t.howItWorks.heading}
        </h2>
        <p className="text-sm text-typography-muted">
          {t.howItWorks.subheading}
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {steps.map((step, idx) => (
          <div
            key={idx}
            className="p-6 rounded-2xl bg-card border border-borderDefault shadow-subtle hover:shadow-card hover:border-primary/30 transition-standard space-y-3 relative"
          >
            <div className="w-12 h-12 rounded-xl bg-surfaceInput border border-borderDefault flex items-center justify-center">
              {step.icon}
            </div>
            <h3 className="text-base font-bold text-typography-headline">
              {step.title}
            </h3>
            <p className="text-xs sm:text-sm text-typography-muted leading-relaxed">
              {step.desc}
            </p>
          </div>
        ))}
      </div>
    </section>
  );
};
