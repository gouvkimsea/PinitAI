import React from 'react';
import { AlertTriangle, CheckCircle2, ShieldAlert } from 'lucide-react';
import type { DetectionSignal, RiskLevel, Language } from '../../types';
import { translations } from '../../i18n/translations';

interface DetectionReasonsProps {
  signals: DetectionSignal[];
  safeFactors: string[];
  riskLevel: RiskLevel;
  lang: Language;
}

export const DetectionReasons: React.FC<DetectionReasonsProps> = ({
  signals,
  safeFactors,
  riskLevel,
  lang,
}) => {
  const t = translations[lang];

  if (riskLevel === 'safe' || signals.length === 0) {
    return (
      <div className="space-y-2.5">
        <h3 className="text-xs font-bold text-typography-headline uppercase tracking-wider flex items-center gap-1.5">
          <CheckCircle2 className="w-4 h-4 text-safe" />
          <span>{t.results.safeHighlights}</span>
        </h3>
        <ul className="space-y-2">
          {safeFactors.map((factor, index) => (
            <li
              key={index}
              className="flex items-start gap-2 text-xs text-typography-body bg-safe-light/40 border border-safe-border/50 p-2.5 rounded-lg"
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-safe mt-0.5 flex-shrink-0" />
              <span>{factor}</span>
            </li>
          ))}
        </ul>
      </div>
    );
  }

  return (
    <div className="space-y-2.5">
      <h3 className="text-xs font-bold text-typography-headline uppercase tracking-wider flex items-center gap-1.5">
        <ShieldAlert className="w-4 h-4 text-danger" />
        <span>{t.results.flaggedTitle}</span>
      </h3>

      <div className="space-y-2">
        {signals.map((signal) => {
          const isHigh = signal.severity === 'high';
          return (
            <div
              key={signal.id}
              className={`p-3 rounded-lg border text-xs transition-standard ${
                isHigh
                  ? 'bg-danger-light/50 border-danger-border/80 text-danger-dark'
                  : 'bg-suspicious-light/50 border-suspicious-border/80 text-suspicious-dark'
              }`}
            >
              <div className="flex items-center justify-between gap-2 font-semibold">
                <span className="flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                  <span>{signal.title}</span>
                </span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-white/70">
                  {signal.severity}
                </span>
              </div>
              <p className="mt-1 text-typography-body text-[11px] leading-relaxed">
                {signal.description}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
};
