import React, { useRef } from 'react';
import { Clipboard, X, Sparkles, MessageSquareWarning } from 'lucide-react';
import type { Language } from '../../types';
import { translations } from '../../i18n/translations';
import { SAMPLE_DATA } from '../../data/samples';

interface TextAnalyzerProps {
  value: string;
  onChange: (val: string) => void;
  lang: Language;
  disabled?: boolean;
}

export const TextAnalyzer: React.FC<TextAnalyzerProps> = ({
  value,
  onChange,
  lang,
  disabled = false,
}) => {
  const t = translations[lang];
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        onChange(text);
        if (textareaRef.current) {
          textareaRef.current.focus();
        }
      }
    } catch {
      // Clipboard access rejected or not available
      if (textareaRef.current) {
        textareaRef.current.focus();
      }
    }
  };

  const handleClear = () => {
    onChange('');
    if (textareaRef.current) {
      textareaRef.current.focus();
    }
  };

  const textSamples = SAMPLE_DATA.filter((s) => s.mode === 'text');

  return (
    <div
      role="tabpanel"
      id="panel-text"
      aria-labelledby="tab-text"
      className="space-y-3"
    >
      <div className="flex items-center justify-between">
        <label
          htmlFor="text-analysis-input"
          className="text-xs font-medium text-typography-muted flex items-center gap-1.5"
        >
          <MessageSquareWarning className="w-3.5 h-3.5 text-primary" />
          <span>{t.textMode.hint}</span>
        </label>

        <div className="flex items-center gap-2">
          {value.trim().length > 0 && (
            <button
              type="button"
              onClick={handleClear}
              disabled={disabled}
              className="text-xs text-typography-muted hover:text-danger flex items-center gap-1 transition-standard px-1.5 py-0.5 rounded cursor-pointer"
              title={t.textMode.clear}
            >
              <X className="w-3.5 h-3.5" />
              <span>{t.textMode.clear}</span>
            </button>
          )}

          <button
            type="button"
            onClick={handlePaste}
            disabled={disabled}
            className="text-xs text-primary hover:text-primary-hover font-medium flex items-center gap-1 transition-standard px-2 py-0.5 rounded bg-primary-soft border border-primary/20 cursor-pointer"
          >
            <Clipboard className="w-3.5 h-3.5" />
            <span>{t.textMode.paste}</span>
          </button>
        </div>
      </div>

      <div className="relative">
        <textarea
          id="text-analysis-input"
          ref={textareaRef}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={t.textMode.placeholder}
          disabled={disabled}
          rows={7}
          className="w-full min-h-[180px] p-4 bg-surfaceInput text-typography-headline placeholder:text-typography-muted/70 rounded-[10px] border border-borderDefault focus:border-borderFocus focus:bg-card focus:outline-none focus:ring-2 focus:ring-primary/20 text-sm leading-relaxed transition-standard resize-y"
        />

        <div className="absolute right-3 bottom-3 pointer-events-none">
          <span className="text-[11px] font-mono text-typography-muted/80 bg-card/80 px-2 py-0.5 rounded border border-borderDefault backdrop-blur-sm">
            {value.length} {t.textMode.charCount}
          </span>
        </div>
      </div>

      {/* Quick Test Samples */}
      <div className="pt-1">
        <p className="text-[11px] font-medium text-typography-muted mb-2 flex items-center gap-1">
          <Sparkles className="w-3 h-3 text-primary" />
          <span>{t.textMode.samplePrompt}</span>
        </p>
        <div className="flex flex-wrap gap-1.5">
          {textSamples.map((sample) => (
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
