import React from 'react';
import type { RiskLevel, Language } from '../../types';
import { translations } from '../../i18n/translations';

interface RiskScoreProps {
  score: number;
  riskLevel: RiskLevel;
  lang: Language;
}

export const RiskScore: React.FC<RiskScoreProps> = ({ score, riskLevel, lang }) => {
  const t = translations[lang];

  // Visual color scheme based on risk
  let barColor = 'bg-safe';
  let badgeBg = 'bg-safe-light border-safe-border text-safe-dark';
  let badgeLabel = t.results.safe.title;

  if (riskLevel === 'high_risk') {
    barColor = 'bg-danger';
    badgeBg = 'bg-danger-light border-danger-border text-danger-dark';
    badgeLabel = t.results.highRisk.title;
  } else if (riskLevel === 'suspicious') {
    barColor = 'bg-suspicious';
    badgeBg = 'bg-suspicious-light border-suspicious-border text-suspicious-dark';
    badgeLabel = t.results.suspicious.title;
  }

  return (
    <div className="p-4 rounded-xl bg-surfaceInput/70 border border-borderDefault space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <span className="text-xs font-semibold text-typography-muted uppercase tracking-wider block">
            {t.results.scoreLabel}
          </span>
          <div className="flex items-baseline gap-1 mt-0.5">
            <span className="text-2xl font-bold text-typography-headline font-mono">
              {score}
            </span>
            <span className="text-xs text-typography-muted font-mono">/ 100</span>
          </div>
        </div>

        <span
          className={`px-3 py-1 rounded-full text-xs font-semibold border ${badgeBg}`}
        >
          {badgeLabel}
        </span>
      </div>

      {/* Visual meter bar */}
      <div className="space-y-1.5">
        <div
          role="progressbar"
          aria-valuenow={score}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`${t.results.scoreLabel}: ${score} out of 100`}
          className="h-2.5 w-full bg-slate-200 rounded-full overflow-hidden"
        >
          <div
            className={`h-full ${barColor} rounded-full transition-all duration-700 ease-out`}
            style={{ width: `${score}%` }}
          />
        </div>

        <div className="flex justify-between text-[10px] text-typography-muted">
          <span>0 (Safe)</span>
          <span>50 (Caution)</span>
          <span>100 (Critical)</span>
        </div>
      </div>
    </div>
  );
};
