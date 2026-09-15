import React, { useEffect, useState } from 'react';
import { Shield, Sparkles, Search, Database, Lock } from 'lucide-react';
import type { Language } from '../types';
import { translations } from '../i18n/translations';

interface LoadingStateProps {
  lang: Language;
}

export const LoadingState: React.FC<LoadingStateProps> = ({ lang }) => {
  const t = translations[lang];
  const [currentStep, setCurrentStep] = useState(0);
  const [progress, setProgress] = useState(15);

  const steps = [
    { text: t.loading.step1, icon: <Search className="w-4 h-4" /> },
    { text: t.loading.step2, icon: <Database className="w-4 h-4" /> },
    { text: t.loading.step3, icon: <Sparkles className="w-4 h-4" /> },
    { text: t.loading.step4, icon: <Lock className="w-4 h-4" /> },
    { text: t.loading.step5, icon: <Shield className="w-4 h-4" /> },
  ];

  useEffect(() => {
    const stepInterval = setInterval(() => {
      setCurrentStep((prev) => (prev < steps.length - 1 ? prev + 1 : prev));
    }, 420);

    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 95) return prev;
        return prev + Math.floor(Math.random() * 8) + 4;
      });
    }, 150);

    return () => {
      clearInterval(stepInterval);
      clearInterval(progressInterval);
    };
  }, [steps.length]);

  return (
    <div
      aria-live="polite"
      aria-busy="true"
      className="py-8 px-4 flex flex-col items-center justify-center text-center space-y-6"
    >
      {/* Animated Radar Shield Icon */}
      <div className="relative flex items-center justify-center">
        <div className="w-20 h-20 rounded-full bg-primary-soft border border-primary/20 flex items-center justify-center text-primary relative">
          <Shield className="w-9 h-9 text-primary animate-pulse" />
          <span className="absolute inset-0 rounded-full border-2 border-primary/30 animate-ping opacity-30" />
        </div>
      </div>

      <div className="space-y-2 max-w-sm">
        <h2 className="text-lg font-bold text-typography-headline">
          {t.actions.analyzing}
        </h2>
        <p className="text-xs text-typography-muted min-h-[20px] transition-all duration-300 font-medium">
          {steps[currentStep].text}
        </p>
      </div>

      {/* Progress Bar */}
      <div className="w-full max-w-xs space-y-1.5">
        <div className="h-1.5 w-full bg-surfaceInput rounded-full overflow-hidden border border-borderDefault">
          <div
            className="h-full bg-primary rounded-full transition-all duration-300 ease-out"
            style={{ width: `${Math.min(progress, 98)}%` }}
          />
        </div>
        <div className="flex justify-between items-center text-[10px] text-typography-muted font-mono px-0.5">
          <span>Multi-signal inspection</span>
          <span>{Math.min(progress, 98)}%</span>
        </div>
      </div>

      {/* Step check indicators */}
      <div className="flex items-center gap-1.5 pt-2">
        {steps.map((_, idx) => (
          <div
            key={idx}
            className={`w-2 h-2 rounded-full transition-all duration-300 ${
              idx <= currentStep
                ? 'bg-primary scale-110'
                : 'bg-borderDefault'
            }`}
          />
        ))}
      </div>
    </div>
  );
};
