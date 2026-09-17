import React, { useEffect } from 'react';
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
  ArrowRight,
} from 'lucide-react';
import type { Language, ScanTab } from '../../types';
import { translations } from '../../i18n/translations';

interface EducationModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
  onTestScam?: (tab: ScanTab, sample: string) => void;
}

export const EducationModal: React.FC<EducationModalProps> = ({
  isOpen,
  onClose,
  lang,
  onTestScam,
}) => {
  const t = translations[lang];
  const isKm = lang === 'km';

  // Handle Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const scamTopics: {
    id: string;
    tab: ScanTab;
    sampleText: string;
    icon: React.ReactNode;
    title: string;
    desc: string;
    redFlags: string[];
    safetyTip: string;
  }[] = [
    {
      id: 'quishing',
      tab: 'qr',
      sampleText: 'https://malicious-qr-redirect.ru/auth/login',
      icon: <QrCode className="w-5 h-5 text-primary" />,
      title: t.education.quishingTitle,
      desc: t.education.quishingDesc,
      redFlags: [
        'Physical stickers pasted over genuine parking or restaurant QR codes',
        'QR prompts demanding immediate credit card details or APK downloads',
      ],
      safetyTip: 'Always preview the decoded URL on Pinit AI before following it on your phone.',
    },
    {
      id: 'phishing',
      tab: 'url',
      sampleText: 'https://paypa1-security-verification.top/signin',
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
      tab: 'message',
      sampleText: 'សូមអបអរសាទរ! អ្នកត្រូវបានជ្រើសរើសសម្រាប់ការងារក្រៅម៉ោង Telegram រកបាន $200-$500/ថ្ងៃ ដោយគ្រាន់តែចុច Like វីដេអូ។ សូមដាក់ប្រាក់កក់ $50 ទៅកាបូប USDT ដើម្បីចាប់ផ្តើម។',
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
      tab: 'message',
      sampleText: 'Exclusive VIP Crypto Signal! Deposit $100 and receive guaranteed 500% profit within 24 hours. Zero risk with automated trading bot. Contact @admin now.',
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
      tab: 'message',
      sampleText: 'URGENT: Your ABA Bank account has suspicious transactions. Send your 6-digit SMS OTP verification code immediately to unlock: http://aba-unlock-verify.top',
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

  const handleTestInScanner = (tab: ScanTab, sample: string) => {
    onClose();
    if (onTestScam) {
      onTestScam(tab, sample);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs animate-fadeIn"
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
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {scamTopics.map((topic) => (
            <div
              key={topic.id}
              className="p-4 rounded-xl border border-borderDefault bg-surfaceInput/30 space-y-3 transition-colors hover:bg-surfaceInput/50"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-card border border-borderDefault">
                    {topic.icon}
                  </div>
                  <h3 className="text-sm font-bold text-typography-headline">{topic.title}</h3>
                </div>
                {onTestScam && (
                  <button
                    type="button"
                    onClick={() => handleTestInScanner(topic.tab, topic.sampleText)}
                    className="inline-flex items-center gap-1 px-3 py-1.5 text-xs font-semibold text-primary bg-primary/10 hover:bg-primary/20 rounded-lg border border-primary/20 transition-all cursor-pointer"
                    title="Test this scam pattern in the threat scanner"
                  >
                    <span>{isKm ? 'សាកល្បងក្នុងម៉ាស៊ីនស្កេន' : 'Test in Scanner'}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
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
