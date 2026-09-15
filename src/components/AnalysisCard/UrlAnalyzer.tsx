import React from 'react';
import { Link2, ShieldCheck, X, Sparkles } from 'lucide-react';
import type { Language } from '../../types';
import { translations } from '../../i18n/translations';
import { SAMPLE_DATA } from '../../data/samples';

interface UrlAnalyzerProps {
  value: string;
  onChange: (val: string) => void;
  lang: Language;
  disabled?: boolean;
}

export const UrlAnalyzer: React.FC<UrlAnalyzerProps> = ({
  value,
  onChange,
  lang,
  disabled = false,
}) => {
  const t = translations[lang];

  const handleClear = () => {
    onChange('');
  };

  const urlSamples = SAMPLE_DATA.filter((s) => s.mode === 'url');

  return (
    <div
      role="tabpanel"
      id="panel-url"
      aria-labelledby="tab-url"
      className="space-y-3"
    >
      <div className="flex items-center justify-between">
        <label
          htmlFor="url-analysis-input"
          className="text-xs font-medium text-typography-muted flex items-center gap-1.5"
        >
          <Link2 className="w-3.5 h-3.5 text-primary" />
          <span>{t.urlMode.hint}</span>
        </label>

        {value.trim().length > 0 && (
          <button
            type="button"
            onClick={handleClear}
            disabled={disabled}
            className="text-xs text-typography-muted hover:text-danger flex items-center gap-1 transition-standard px-1.5 py-0.5 rounded cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
            <span>{t.textMode.clear}</span>
          </button>
        )}
      </div>

      <div className="relative flex items-center">
        <div className="absolute left-3.5 text-typography-muted pointer-events-none">
          <Link2 className="w-4 h-4" />
        </div>
        <input
          type="url"
          id="url-analysis-input"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={t.urlMode.placeholder}
          disabled={disabled}
          className="w-full pl-10 pr-10 py-3.5 bg-surfaceInput text-typography-headline placeholder:text-typography-muted/70 rounded-[10px] border border-borderDefault focus:border-borderFocus focus:bg-card focus:outline-none focus:ring-2 focus:ring-primary/20 text-sm font-mono transition-standard"
        />
        {value.trim().length > 0 && (
          <button
            type="button"
            onClick={handleClear}
            disabled={disabled}
            className="absolute right-3 text-typography-muted hover:text-typography-headline"
            aria-label="Clear URL"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Security sandbox disclaimer banner */}
      <div className="flex items-start gap-2 p-2.5 rounded-lg bg-surfaceInput/60 border border-borderDefault text-[11px] text-typography-muted">
        <ShieldCheck className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
        <p className="leading-normal">{t.urlMode.caution}</p>
      </div>

      {/* Quick Test Samples */}
      <div className="pt-1">
        <p className="text-[11px] font-medium text-typography-muted mb-2 flex items-center gap-1">
          <Sparkles className="w-3 h-3 text-primary" />
          <span>{t.urlMode.samplePrompt}</span>
        </p>
        <div className="flex flex-wrap gap-1.5">
          {urlSamples.map((sample) => (
            <button
              key={sample.id}
              type="button"
              disabled={disabled}
              onClick={() => onChange(sample.content)}
              className={`text-xs px-2.5 py-1 rounded-lg border transition-standard text-left cursor-pointer ${
                value === sample.content
                  ? 'bg-primary-soft border-primary/40 text-primary font-medium shadow-xs'
                  : 'bg-card hover:bg-surfaceInput border-borderDefault text-typography-body hover:border-slate-300'
              }`}
            >
              <span className="font-medium">{sample.title}</span>
              <span className="ml-1 text-[10px] text-typography-muted">
                ({sample.badge})
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
