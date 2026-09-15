import React from 'react';
import { X, ShieldCheck, HeartHandshake, EyeOff } from 'lucide-react';
import type { Language } from '../../types';

interface AboutModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
}

export const AboutModal: React.FC<AboutModalProps> = ({ isOpen, onClose, lang }) => {
  const isKm = lang === 'km';

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="about-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-fadeIn"
    >
      <div className="w-full max-w-xl max-h-[90vh] overflow-y-auto bg-card rounded-2xl border border-borderDefault shadow-elevated p-6 relative space-y-5">
        <button
          type="button"
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-typography-muted hover:text-typography-headline rounded-lg hover:bg-surfaceInput transition-standard"
          aria-label="Close modal"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h2 id="about-modal-title" className="text-lg font-bold text-typography-headline">
              {isKm ? 'អំពី ScamCheck AI' : 'About ScamCheck AI'}
            </h2>
            <p className="text-xs text-typography-muted">
              {isKm ? 'សន្តិសុខឌីជីថលសាមញ្ញ សម្រាប់មនុស្សគ្រប់គ្នា' : 'Simple, Accessible Cybersecurity for Everyone'}
            </p>
          </div>
        </div>

        <div className="space-y-3 text-xs leading-relaxed text-typography-body">
          <p>
            {isKm
              ? 'ScamCheck AI ត្រូវបានបង្កើតឡើងក្នុងគោលបំណងជួយប្រជាពលរដ្ឋទូទៅការពារខ្លួនពីការឆបោកតាមប្រព័ន្ធឌីជីថល។ យើងជឿជាក់ថា សន្តិសុខតាមអ៊ីនធឺណិតមិនគួរមានភាពស្មុគស្មាញ ឬគួរឱ្យខ្លាចនោះទេ។'
              : 'ScamCheck AI was engineered with a clear mission: make digital defense accessible, calm, and immediate for everyday users without cybersecurity background.'}
          </p>
          <p>
            {isKm
              ? 'ប្រព័ន្ធរបស់យើងដំណើរការវិភាគពហុស្រទាប់ រួមមាន៖ ការពិនិត្យពាក្យសម្ដីបង្ខំពេលវេលា ភាពមិនប្រក្រតីនៃដែនគេហទំព័រ ការក្លែងបន្លំយីហោ និងការស្នើសុំទូទាត់ប្រាក់ដែលមិនអាចដកវិញបាន។'
              : 'Our system runs automated multi-signal checks that identify artificial urgency, brand impersonation, typosquatted links, and irreversible payment channels.'}
          </p>
        </div>

        <div className="space-y-2 pt-2 border-t border-borderDefault">
          <h3 className="text-xs font-bold text-typography-headline uppercase tracking-wider">
            {isKm ? 'គោលការណ៍ស្នូលរបស់យើង' : 'Core Product Principles'}
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            <div className="p-3 rounded-lg bg-surfaceInput border border-borderDefault space-y-1">
              <div className="flex items-center gap-1.5 font-semibold text-typography-headline text-xs">
                <EyeOff className="w-4 h-4 text-primary" />
                <span>{isKm ? 'ភាពឯកជនដាច់ខាត' : 'Zero Data Retention'}</span>
              </div>
              <p className="text-[11px] text-typography-muted">
                {isKm
                  ? 'ទិន្នន័យស្កេនត្រូវបានដំណើរការក្នុងអង្គចងចាំបណ្តោះអាសន្ន និងមិនត្រូវរក្សាទុកឡើយ។'
                  : 'Submitted snippets and files are processed in ephemeral memory and never logged.'}
              </p>
            </div>

            <div className="p-3 rounded-lg bg-surfaceInput border border-borderDefault space-y-1">
              <div className="flex items-center gap-1.5 font-semibold text-typography-headline text-xs">
                <HeartHandshake className="w-4 h-4 text-safe" />
                <span>{isKm ? 'ការណែនាំសាមញ្ញ' : 'No Jargon Guidance'}</span>
              </div>
              <p className="text-[11px] text-typography-muted">
                {isKm
                  ? 'លទ្ធផលពន្យល់ជាភាសាងាយយល់ ជាមួយនឹងជំហានការពារខ្លួនជាក់ស្តែង។'
                  : 'Plain-language summaries and straightforward actions instead of cryptic CVE codes.'}
              </p>
            </div>
          </div>
        </div>

        <div className="pt-2 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium rounded-lg bg-primary text-white hover:bg-primary-hover transition-standard cursor-pointer"
          >
            {isKm ? 'យល់ព្រម' : 'Got it'}
          </button>
        </div>
      </div>
    </div>
  );
};
