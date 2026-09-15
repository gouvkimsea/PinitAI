import React from 'react';
import { ArrowRight, Loader2, Sparkles } from 'lucide-react';
import type { Language } from '../../types';
import { translations } from '../../i18n/translations';

interface AnalyzeButtonProps {
  onClick: () => void;
  isLoading: boolean;
  disabled?: boolean;
  lang: Language;
}

export const AnalyzeButton: React.FC<AnalyzeButtonProps> = ({
  onClick,
  isLoading,
  disabled = false,
  lang,
}) => {
  const t = translations[lang];

  return (
    <button
      type="button"
      id="analyze-submit-button"
      onClick={onClick}
      disabled={disabled || isLoading}
      className={`w-full h-12 md:h-[50px] px-6 rounded-[10px] bg-primary text-white font-semibold text-sm md:text-base flex items-center justify-center gap-2 shadow-sm transition-standard cursor-pointer select-none ${
        disabled || isLoading
          ? 'opacity-60 cursor-not-allowed'
          : 'hover:bg-primary-hover hover:shadow active:scale-[0.99] focus-visible:ring-2 focus-visible:ring-primary/40 focus-visible:ring-offset-2'
      }`}
    >
      {isLoading ? (
        <>
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>{t.actions.analyzing}</span>
        </>
      ) : (
        <>
          <Sparkles className="w-4 h-4" />
          <span>{t.actions.analyzeNow}</span>
          <ArrowRight className="w-4 h-4 ml-0.5 group-hover:translate-x-0.5 transition-standard" />
        </>
      )}
    </button>
  );
};
