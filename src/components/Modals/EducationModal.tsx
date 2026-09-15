import React from 'react';
import {
  X,
  BookOpen,
  QrCode,
  Globe,
  Briefcase,
  TrendingUp,
  KeyRound,
  CheckCircle,
  AlertTriangle,
} from 'lucide-react';
import type { Language } from '../../types';
import { translations } from '../../i18n/translations';

interface EducationModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
}

export const EducationModal: React.FC<EducationModalProps> = ({
  isOpen,
  onClose,
  lang,
}) => {
  const t = translations[lang];

  if (!isOpen) return null;

  const scamTopics = [
    {
      id: 'quishing',
      icon: <QrCode className="w-5 h-5 text-primary" />,
      title: t.education.quishingTitle,
      desc: t.education.quishingDesc,
      redFlags: [
        'Physical stickers pasted over genuine parking or restaurant QR codes',
        'QR prompts demanding immediate credit card details or APK downloads',
      ],
      safetyTip: 'Always preview the decoded URL on ScamCheck AI before following it on your phone.',
    },
    {
      id: 'phishing',
      icon: <Globe className="w-5 h-5 text-danger" />,
      title: t.education.phishingTitle,
      desc: t.education.phishingDesc,
      redFlags: [
        'Slightly altered URLs (e.g., paypa1.com or aba-verify.top)',
        'Urgent claims that your account will be suspended within 24 hours',
      ],
      safetyTip: 'Bookmark official banking portals and never click verification links sent via SMS.',
    },
    {
      id: 'jobs',
      icon: <Briefcase className="w-5 h-5 text-warning" />,
      title: t.education.jobTitle,
      desc: t.education.jobDesc,
      redFlags: [
        'Promises of $100–$500 daily for clicking like on social videos',
        'Requirement to deposit your own money into a crypto wallet to unlock VIP tasks',
      ],
      safetyTip: 'Legitimate employers never require payment or cryptocurrency deposits from job applicants.',
    },
    {
      id: 'crypto',
      icon: <TrendingUp className="w-5 h-5 text-suspicious" />,
      title: t.education.investTitle,
      desc: t.education.investDesc,
      redFlags: [
        'Promises of guaranteed 100% returns in 24 hours with zero risk',
        'Unsolicited recommendations from romantic acquaintances on WhatsApp/Telegram',
      ],
      safetyTip: 'All high-return investment guarantees are fraudulent. Only use licensed brokers.',
    },
    {
      id: 'otp',
      icon: <KeyRound className="w-5 h-5 text-danger" />,
      title: t.education.otpTitle,
      desc: t.education.otpDesc,
      redFlags: [
        'Callers claiming to be bank security demanding your 6-digit SMS OTP code',
        'Emergency verification requests received late at night',
      ],
      safetyTip: 'Bank staff will never ask for your one-time passwords or card CVV codes.',
    },
  ];

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-fadeIn"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-3xl max-h-[90vh] flex flex-col bg-card rounded-2xl border border-borderDefault shadow-dialog overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-borderDefault bg-surfaceInput/40">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-primary/10 text-primary">
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-typography-headline">
                {t.education.heading}
              </h2>
              <p className="text-xs text-typography-muted">{t.education.subheading}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-2 rounded-lg text-typography-muted hover:text-typography-body hover:bg-card border border-borderDefault transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {scamTopics.map((topic) => (
            <div
              key={topic.id}
              className="p-4 rounded-xl border border-borderDefault bg-surfaceInput/30 space-y-2.5 transition-colors hover:bg-surfaceInput/50"
            >
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-card border border-borderDefault">
                  {topic.icon}
                </div>
                <h3 className="text-sm font-bold text-typography-headline">{topic.title}</h3>
              </div>
              <p className="text-xs text-typography-body leading-relaxed">{topic.desc}</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1">
                <div className="p-2.5 rounded-lg bg-danger-light/40 border border-danger-border/40 text-[11px] text-danger-dark space-y-1">
                  <span className="font-semibold uppercase tracking-wider flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" />
                    <span>Warning Signs</span>
                  </span>
                  <ul className="list-disc list-inside space-y-0.5 text-typography-body">
                    {topic.redFlags.map((flag, idx) => (
                      <li key={idx}>{flag}</li>
                    ))}
                  </ul>
                </div>
                <div className="p-2.5 rounded-lg bg-safe-light/40 border border-safe-border/40 text-[11px] text-safe-dark space-y-1">
                  <span className="font-semibold uppercase tracking-wider flex items-center gap-1">
                    <CheckCircle className="w-3 h-3" />
                    <span>How to Stay Safe</span>
                  </span>
                  <p className="text-typography-body">{topic.safetyTip}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
