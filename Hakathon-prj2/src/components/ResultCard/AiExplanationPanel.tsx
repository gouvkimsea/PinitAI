import React, { useState } from 'react';
import {
  Sparkles,
  AlertTriangle,
  ShieldQuestion,
  ListChecks,
  Target,
  MessageSquareWarning,
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  XCircle,
  Info,
  Cpu,
  Bot,
} from 'lucide-react';
import type { AiStructuredExplanation } from '../../types';

interface AiExplanationPanelProps {
  explanation: AiStructuredExplanation;
  /** Suppress full panel; show only the why_suspicious callout */
  compact?: boolean;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high:     'bg-orange-100 text-orange-800 border-orange-200',
  medium:   'bg-yellow-100 text-yellow-700 border-yellow-200',
  low:      'bg-blue-100 text-blue-700 border-blue-200',
};

const CONFIDENCE_LABEL: Record<string, string> = {
  very_low: 'Very Low',
  low:      'Low',
  medium:   'Medium',
  high:     'High',
  verified: 'Verified',
};

const CONFIDENCE_COLOR: Record<string, string> = {
  very_low: 'text-red-600',
  low:      'text-orange-600',
  medium:   'text-yellow-600',
  high:     'text-emerald-600',
  verified: 'text-emerald-700 font-bold',
};

/**
 * AiExplanationPanel — renders the full 5-part structured AI explanation.
 *
 * Sections:
 * 1. Why Suspicious (narrative, always visible)
 * 2. Triggered Signals (collapsible list)
 * 3. Scam Type (category card)
 * 4. What To Do (actionable advice)
 * 5. Uncertainty Notice (prominent if is_uncertain)
 */
export const AiExplanationPanel: React.FC<AiExplanationPanelProps> = ({
  explanation,
  compact = false,
}) => {
  const [expanded, setExpanded] = useState(false);

  const {
    why_suspicious,
    triggered_signals,
    scam_type,
    actionable_advice,
    uncertainty_notes,
    generated_by,
    ai_generated,
    verified_signal_count,
    evidence_summary,
    grounded_in_evidence,
  } = explanation;

  const isAiGenerated = ai_generated || generated_by === 'ai_model';
  const isUncertain = uncertainty_notes?.is_uncertain ?? false;

  // ── Compact mode: just the callout + provenance badge ──────────────────────
  if (compact) {
    return (
      <div className="p-3.5 rounded-xl bg-primary-light/40 border border-primary/20 text-xs text-typography-body flex items-start gap-2.5">
        <Sparkles className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
        <div>
          <div className="flex items-center gap-1.5 mb-0.5">
            <span className="font-semibold text-primary">AI Security Explanation</span>
            {isAiGenerated ? (
              <span className="px-1.5 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider bg-primary/10 text-primary border border-primary/20 flex items-center gap-0.5">
                <Bot className="w-2.5 h-2.5" /> AI
              </span>
            ) : (
              <span className="px-1.5 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider bg-gray-100 text-gray-500 border border-gray-200 flex items-center gap-0.5">
                <Cpu className="w-2.5 h-2.5" /> Rules
              </span>
            )}
          </div>
          <p className="leading-relaxed text-[11px] sm:text-xs">{why_suspicious}</p>
        </div>
      </div>
    );
  }

  // ── Full panel ──────────────────────────────────────────────────────────────
  return (
    <div className="rounded-2xl border border-primary/25 bg-gradient-to-br from-primary-light/30 to-primary-light/10 overflow-hidden shadow-sm">
      {/* ── Panel Header ── */}
      <div className="px-4 py-3 flex items-center justify-between bg-primary/8 border-b border-primary/15">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-primary" />
          <span className="text-sm font-bold text-primary">AI Security Analysis</span>
          {isAiGenerated ? (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-primary text-white flex items-center gap-1">
              <Bot className="w-3 h-3" /> Gemini AI
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-gray-200 text-gray-600 flex items-center gap-1">
              <Cpu className="w-3 h-3" /> Rules Engine
            </span>
          )}
        </div>
        {grounded_in_evidence && (
          <span className="text-[10px] text-emerald-600 flex items-center gap-1 font-medium">
            <CheckCircle2 className="w-3 h-3" />
            Evidence-Grounded
          </span>
        )}
      </div>

      <div className="p-4 space-y-4">

        {/* ── SECTION 1: Uncertainty Notice (shown at top when uncertain) ── */}
        {isUncertain && (
          <div className="p-3 rounded-xl bg-amber-50 border border-amber-200 flex items-start gap-2.5">
            <MessageSquareWarning className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
            <div className="text-xs">
              <span className="font-bold text-amber-800 block mb-0.5">
                ⚠️ Uncertain Result — Insufficient Evidence
              </span>
              <p className="text-amber-700 leading-relaxed">
                {uncertainty_notes.reason}
              </p>
              {uncertainty_notes.missing_information.length > 0 && (
                <ul className="mt-1.5 space-y-0.5">
                  {uncertainty_notes.missing_information.map((info, i) => (
                    <li key={i} className="flex items-start gap-1 text-amber-600">
                      <Info className="w-3 h-3 flex-shrink-0 mt-0.5" />
                      <span>{info}</span>
                    </li>
                  ))}
                </ul>
              )}
              <div className="mt-1.5 text-[10px] font-semibold text-amber-600">
                Confidence Level:{' '}
                <span className={CONFIDENCE_COLOR[uncertainty_notes.confidence_level] || 'text-amber-600'}>
                  {CONFIDENCE_LABEL[uncertainty_notes.confidence_level] || uncertainty_notes.confidence_level}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* ── SECTION 1: Why Suspicious ── */}
        <div className="space-y-1.5">
          <div className="flex items-center gap-1.5">
            <ShieldQuestion className="w-3.5 h-3.5 text-primary" />
            <span className="text-[11px] font-bold uppercase tracking-wider text-typography-muted">
              Why This Was Flagged
            </span>
          </div>
          <p className="text-xs text-typography-body leading-relaxed pl-5">
            {why_suspicious}
          </p>
        </div>

        {/* ── SECTION 2: Triggered Signals ── */}
        {triggered_signals && triggered_signals.length > 0 && (
          <div className="space-y-1.5">
            <button
              type="button"
              onClick={() => setExpanded(!expanded)}
              className="w-full flex items-center justify-between cursor-pointer group"
            >
              <div className="flex items-center gap-1.5">
                <ListChecks className="w-3.5 h-3.5 text-primary" />
                <span className="text-[11px] font-bold uppercase tracking-wider text-typography-muted group-hover:text-primary transition-colors">
                  Triggered Signals ({triggered_signals.length})
                </span>
              </div>
              {expanded ? (
                <ChevronUp className="w-3.5 h-3.5 text-typography-muted" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5 text-typography-muted" />
              )}
            </button>
            {expanded && (
              <div className="pl-5 space-y-1.5 animate-fadeIn">
                {triggered_signals.map((sig, idx) => (
                  <div
                    key={idx}
                    className={`flex items-start gap-2 p-2 rounded-lg border text-[11px] ${
                      SEVERITY_STYLES[sig.severity] || SEVERITY_STYLES['medium']
                    }`}
                  >
                    <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="font-semibold">{sig.signal}</span>
                        <span className="text-[9px] font-bold uppercase px-1 py-0 rounded bg-white/60 border border-current/20">
                          {sig.severity}
                        </span>
                      </div>
                      {sig.detail && sig.detail !== sig.signal && (
                        <p className="mt-0.5 opacity-80 leading-relaxed">{sig.detail}</p>
                      )}
                      {sig.source_detector && (
                        <span className="text-[9px] opacity-60 font-mono mt-0.5 block">
                          Source: {sig.source_detector}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ── SECTION 3: Scam Type ── */}
        {scam_type && scam_type.category !== 'safe_content' && (
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5">
              <Target className="w-3.5 h-3.5 text-primary" />
              <span className="text-[11px] font-bold uppercase tracking-wider text-typography-muted">
                Potential Threat Type
              </span>
            </div>
            <div className="pl-5">
              <div className="p-2.5 rounded-lg border border-primary/20 bg-primary-light/20 text-xs">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-bold text-typography-headline">{scam_type.name}</span>
                  <span
                    className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded-full border ${
                      scam_type.threat_level === 'CRITICAL' ? 'bg-red-100 text-red-700 border-red-200' :
                      scam_type.threat_level === 'HIGH'     ? 'bg-orange-100 text-orange-700 border-orange-200' :
                      scam_type.threat_level === 'SUSPICIOUS' ? 'bg-yellow-100 text-yellow-700 border-yellow-200' :
                                                                'bg-blue-100 text-blue-700 border-blue-200'
                    }`}
                  >
                    {scam_type.threat_level}
                  </span>
                </div>
                <p className="mt-1 text-typography-body leading-relaxed">{scam_type.description}</p>
              </div>
            </div>
          </div>
        )}

        {/* ── SECTION 4: What To Do ── */}
        {actionable_advice && actionable_advice.length > 0 && (
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-primary" />
              <span className="text-[11px] font-bold uppercase tracking-wider text-typography-muted">
                What You Should Do
              </span>
            </div>
            <ul className="pl-5 space-y-1.5">
              {actionable_advice.map((advice, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-typography-body">
                  <span className="mt-0.5 w-4 h-4 rounded-full bg-primary/10 text-primary flex-shrink-0 flex items-center justify-center text-[9px] font-bold">
                    {idx + 1}
                  </span>
                  <span className="leading-relaxed">{advice}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* ── SECTION 5: Uncertainty (bottom, when evidence is sufficient) ── */}
        {!isUncertain && uncertainty_notes && (
          <div className="flex items-start gap-2 text-[11px] text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg p-2.5">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-emerald-600" />
            <div>
              <span className="font-semibold block mb-0.5">Evidence Assessment</span>
              <p className="leading-relaxed text-emerald-700">{uncertainty_notes.reason}</p>
              <div className="mt-1 text-[10px]">
                Confidence:{' '}
                <span className={CONFIDENCE_COLOR[uncertainty_notes.confidence_level] || ''}>
                  {CONFIDENCE_LABEL[uncertainty_notes.confidence_level] || uncertainty_notes.confidence_level}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* ── Grounding Metadata Footer ── */}
        <div className="pt-1 border-t border-primary/10 flex items-center justify-between text-[10px] text-typography-muted">
          <span className="flex items-center gap-1">
            {grounded_in_evidence ? (
              <><CheckCircle2 className="w-3 h-3 text-emerald-500" /> Grounded in evidence</>
            ) : (
              <><XCircle className="w-3 h-3 text-red-400" /> Unverified</>
            )}
          </span>
          {verified_signal_count !== undefined && (
            <span className="font-mono">{verified_signal_count} verified signal{verified_signal_count !== 1 ? 's' : ''}</span>
          )}
          {evidence_summary && (
            <span className="hidden sm:block truncate max-w-[200px] text-right">{evidence_summary}</span>
          )}
        </div>

      </div>
    </div>
  );
};
