import React from 'react';
import { ShieldCheck, RotateCcw, Copy, Check, Flag, AlertCircle, Download } from 'lucide-react';
import type { RiskLevel, Language } from '../../types';
import { translations } from '../../i18n/translations';

interface RecommendedActionProps {
  riskLevel: RiskLevel;
  recommendations: string[];
  onReset: () => void;
  onCopyReport: () => void;
  onExportJson?: () => void;
  onReportScam: () => void;
  isCopied: boolean;
  lang: Language;
}

export const RecommendedAction: React.FC<RecommendedActionProps> = ({
  riskLevel,
  recommendations,
  onReset,
  onCopyReport,
  onExportJson,
  onReportScam,
  isCopied,
  lang,
}) => {
  const t = translations[lang];

  // Primary directive title based on risk
  let bannerBg = 'bg-safe-light border-safe-border text-safe-dark';
  let bannerIcon = <ShieldCheck className="w-5 h-5 text-safe" />;
  let primaryDirective = t.results.safe.recommendation;

  if (riskLevel === 'high_risk') {
    bannerBg = 'bg-danger-light border-danger-border text-danger-dark';
    bannerIcon = <AlertCircle className="w-5 h-5 text-danger" />;
    primaryDirective = t.results.highRisk.recommendation;
  } else if (riskLevel === 'suspicious') {
    bannerBg = 'bg-suspicious-light border-suspicious-border text-suspicious-dark';
    bannerIcon = <AlertCircle className="w-5 h-5 text-suspicious" />;
    primaryDirective = t.results.suspicious.recommendation;
  }

  return (
    <div className="space-y-4">
      {/* Recommended Action Box */}
      <div className={`p-4 rounded-xl border ${bannerBg} space-y-2`}>
        <div className="flex items-center gap-2">
          {bannerIcon}
          <h3 className="text-xs font-bold uppercase tracking-wider">
            {t.results.recommendedTitle}
          </h3>
        </div>

        <p className="text-sm font-semibold leading-relaxed">
          {primaryDirective}
        </p>

        {/* Detailed checklist */}
        <ul className="space-y-1.5 pt-2 border-t border-black/5">
          {recommendations.map((rec, index) => (
            <li key={index} className="text-xs flex items-start gap-2 text-typography-body">
              <span className="w-1.5 h-1.5 rounded-full bg-current mt-1.5 flex-shrink-0" />
              <span>{rec}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Action Buttons */}
      <div className="flex flex-col sm:flex-row items-center gap-2 pt-1">
        <button
          type="button"
          onClick={onReset}
          className="w-full sm:flex-1 h-11 px-4 rounded-lg bg-primary text-white font-medium text-xs sm:text-sm flex items-center justify-center gap-2 hover:bg-primary-hover shadow-subtle transition-standard cursor-pointer"
        >
          <RotateCcw className="w-4 h-4" />
          <span>{t.actions.checkAnother}</span>
        </button>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <button
            type="button"
            onClick={onCopyReport}
            className="flex-1 sm:flex-none h-11 px-3.5 rounded-lg bg-card hover:bg-surfaceInput border border-borderDefault text-typography-body font-medium text-xs flex items-center justify-center gap-1.5 transition-standard cursor-pointer"
            title={t.actions.copyReport}
          >
            {isCopied ? (
              <>
                <Check className="w-4 h-4 text-safe" />
                <span className="text-safe font-semibold">{t.actions.copied}</span>
              </>
            ) : (
              <>
                <Copy className="w-4 h-4 text-typography-muted" />
                <span>{t.actions.copyReport}</span>
              </>
            )}
          </button>

          {onExportJson && (
            <button
              type="button"
              onClick={onExportJson}
              className="flex-1 sm:flex-none h-11 px-3 rounded-lg bg-card hover:bg-surfaceInput border border-borderDefault text-typography-body font-medium text-xs flex items-center justify-center gap-1.5 transition-standard cursor-pointer"
              title={t.actions.exportJson}
            >
              <Download className="w-4 h-4 text-typography-muted" />
              <span className="hidden sm:inline">{t.actions.exportJson}</span>
              <span className="sm:hidden">JSON</span>
            </button>
          )}

          {riskLevel !== 'safe' && (
            <button
              type="button"
              onClick={onReportScam}
              className="flex-1 sm:flex-none h-11 px-3.5 rounded-lg bg-card hover:bg-danger-light/40 border border-borderDefault hover:border-danger-border text-typography-body hover:text-danger font-medium text-xs flex items-center justify-center gap-1.5 transition-standard cursor-pointer"
            >
              <Flag className="w-4 h-4 text-danger" />
              <span>{t.actions.reportScam}</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
