import React, { useState, useEffect } from 'react';
import { X, ShieldCheck, HeartHandshake, EyeOff, Award, CheckCircle } from 'lucide-react';
import type { Language } from '../../types';

export type AboutModalTab = 'about' | 'privacy' | 'terms' | 'accessibility';

interface AboutModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
  initialTab?: AboutModalTab;
}

export const AboutModal: React.FC<AboutModalProps> = ({
  isOpen,
  onClose,
  lang,
  initialTab = 'about',
}) => {
  const isKm = lang === 'km';
  const [activeTab, setActiveTab] = useState<AboutModalTab>(initialTab);
  const [prevOpen, setPrevOpen] = useState(isOpen);
  const [prevInitialTab, setPrevInitialTab] = useState(initialTab);

  if (isOpen !== prevOpen || initialTab !== prevInitialTab) {
    setPrevOpen(isOpen);
    setPrevInitialTab(initialTab);
    setActiveTab(initialTab);
  }

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

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="about-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs animate-fadeIn"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl max-h-[90vh] flex flex-col bg-white rounded-2xl border border-slate-200 shadow-2xl overflow-hidden relative"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header matching Pinit Theme */}
        <div className="bg-[#0b3e6e] text-white p-5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-white/10 border border-white/20 flex items-center justify-center text-sky-300">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 id="about-modal-title" className="text-sm sm:text-base font-bold text-white">
                {isKm ? 'ព័ត៌មាន និងលក្ខខណ្ឌ Pinit AI' : 'Pinit AI Trust & Compliance'}
              </h2>
              <p className="text-[11px] text-sky-200">
                {isKm ? 'សន្តិសុខឌីជីថលសាមញ្ញ សម្រាប់មនុស្សគ្រប់គ្នា' : 'Simple, Accessible Cybersecurity for Everyone'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-slate-300 hover:text-white rounded-lg hover:bg-white/10 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 px-5 py-2.5 border-b border-slate-200 bg-slate-50 text-xs font-semibold overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveTab('about')}
            className={`px-3 py-1.5 rounded-lg transition-all shrink-0 cursor-pointer ${
              activeTab === 'about'
                ? 'bg-[#0b3e6e] text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
            }`}
          >
            {isKm ? 'អំពី Pinit' : 'About Pinit'}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('privacy')}
            className={`px-3 py-1.5 rounded-lg transition-all shrink-0 cursor-pointer ${
              activeTab === 'privacy'
                ? 'bg-[#0b3e6e] text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
            }`}
          >
            {isKm ? 'គោលការណ៍ឯកជនភាព' : 'Privacy Policy'}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('terms')}
            className={`px-3 py-1.5 rounded-lg transition-all shrink-0 cursor-pointer ${
              activeTab === 'terms'
                ? 'bg-[#0b3e6e] text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
            }`}
          >
            {isKm ? 'លក្ខខណ្ឌប្រើប្រាស់' : 'Terms of Protection'}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('accessibility')}
            className={`px-3 py-1.5 rounded-lg transition-all shrink-0 cursor-pointer ${
              activeTab === 'accessibility'
                ? 'bg-[#0b3e6e] text-white shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/60'
            }`}
          >
            {isKm ? 'ភាពងាយស្រួល (WCAG AA)' : 'Accessibility (WCAG AA)'}
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 text-xs leading-relaxed text-slate-700">
          {activeTab === 'about' && (
            <div className="space-y-4 animate-fadeIn">
              <div>
                <h3 className="text-sm font-bold text-[#09355e] mb-1">
                  {isKm ? 'បេសកកម្មរបស់យើង' : 'Our Defensive Mission'}
                </h3>
                <p>
                  {isKm
                    ? 'Pinit AI ត្រូវបានបង្កើតឡើងក្នុងគោលបំណងជួយប្រជាពលរដ្ឋទូទៅការពារខ្លួនពីការឆបោកតាមប្រព័ន្ធឌីជីថល។ យើងជឿជាក់ថា សន្តិសុខតាមអ៊ីនធឺណិតមិនគួរមានភាពស្មុគស្មាញ ឬគួរឱ្យខ្លាចនោះទេ។'
                    : 'Pinit AI was engineered to make cyber defense calm, immediate, and accessible for everyone. We believe identifying digital scams, malicious links, and infected files should take two clicks, not an advanced engineering degree.'}
                </p>
              </div>

              <div>
                <h3 className="text-sm font-bold text-[#09355e] mb-1">
                  {isKm ? 'បច្ចេកវិទ្យាវិភាគពហុស្រទាប់' : 'Multi-Modal Defensive Intelligence'}
                </h3>
                <p>
                  {isKm
                    ? 'ប្រព័ន្ធរបស់យើងដំណើរការវិភាគពហុស្រទាប់ រួមមាន៖ ការពិនិត្យពាក្យសម្ដីបង្ខំពេលវេលា ភាពមិនប្រក្រតីនៃដែនគេហទំព័រ ការក្លែងបន្លំយីហោ និងការស្នើសុំទូទាត់ប្រាក់ដែលមិនអាចដកវិញបាន។'
                    : 'Our platform coordinates ClamAV antivirus inspection, QR code sandbox decoding, machine learning heuristic classification, brand typosquatting detection, and Google Gemini threat reasoning to analyze files, URLs, QR codes, and SMS/Telegram messages.'}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-200">
                <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider mb-2">
                  {isKm ? 'គោលការណ៍ស្នូល' : 'Core Product Principles'}
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                    <div className="flex items-center gap-1.5 font-semibold text-slate-800 text-xs">
                      <EyeOff className="w-4 h-4 text-[#0b4d82]" />
                      <span>{isKm ? 'ភាពឯកជនដាច់ខាត' : 'Zero Data Retention'}</span>
                    </div>
                    <p className="text-[11px] text-slate-500">
                      {isKm
                        ? 'ទិន្នន័យស្កេនត្រូវបានដំណើរការក្នុងអង្គចងចាំបណ្តោះអាសន្ន និងមិនត្រូវរក្សាទុកឡើយ។'
                        : 'Submitted content is checked in ephemeral memory and discarded immediately.'}
                    </p>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 space-y-1">
                    <div className="flex items-center gap-1.5 font-semibold text-slate-800 text-xs">
                      <HeartHandshake className="w-4 h-4 text-emerald-600" />
                      <span>{isKm ? 'ការណែនាំសាមញ្ញ' : 'Plain-Language Safety'}</span>
                    </div>
                    <p className="text-[11px] text-slate-500">
                      {isKm
                        ? 'លទ្ធផលពន្យល់ជាភាសាងាយយល់ ជាមួយនឹងជំហានការពារខ្លួនជាក់ស្តែង។'
                        : 'Actionable steps and plain-English explanations instead of cryptic vulnerability codes.'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'privacy' && (
            <div className="space-y-4 animate-fadeIn">
              <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 flex items-start gap-2.5">
                <ShieldCheck className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-emerald-900 text-xs">
                    {isKm ? 'ការប្តេជ្ញាចិត្តលើការការពារទិន្នន័យ (Zero Data Retention)' : 'Zero-Retention Guarantee'}
                  </h4>
                  <p className="text-[11px] text-emerald-800 mt-0.5">
                    {isKm
                      ? 'យើងមិនលក់ មិនចែករំលែក និងមិនរក្សាទុកសារផ្ទាល់ខ្លួន ឬឯកសារសម្ងាត់របស់អ្នកឡើយ។'
                      : 'Pinit AI processes uploaded files and message bodies inside isolated sandbox memory buffers. Files are automatically unlinked and permanently purged upon scan completion.'}
                  </p>
                </div>
              </div>

              <div>
                <h3 className="text-sm font-bold text-[#09355e] mb-1">
                  {isKm ? 'ព័ត៌មានដែលយើងដំណើរការ' : 'Data Processed During Analysis'}
                </h3>
                <ul className="list-disc list-inside space-y-1 text-slate-600 text-[11px]">
                  <li><strong>Cryptographic Hashes:</strong> We compute SHA-256 and MD5 hashes of uploaded files to cross-reference global malware threat feeds without storing the underlying file content.</li>
                  <li><strong>URL Targets:</strong> Destination domains and URL redirects are parsed for typosquatting, spoofing, and SSL certificate validity.</li>
                  <li><strong>Diagnostic Telemetry:</strong> Anonymized response latencies and detector error codes are logged for performance monitoring with IP masking.</li>
                </ul>
              </div>

              <div>
                <h3 className="text-sm font-bold text-[#09355e] mb-1">
                  {isKm ? 'ខូឃី និងការតាមដាន' : 'No Tracking Cookies'}
                </h3>
                <p>
                  {isKm
                    ? 'គេហទំព័រនេះមិនប្រើប្រាស់ខូឃីតាមដានពាណិជ្ជកម្មឡើយ។ ការផ្ទុកតែមួយគត់គឺលេខកូដ Token ចូលប្រើរបស់អ្នកក្នុងឧបករណ៍របស់អ្នកផ្ទាល់។'
                    : 'We do not use advertising trackers, behavioral fingerprinting, or cross-site tracking cookies. Authentication state is stored locally in client localStorage and can be cleared anytime by logging out.'}
                </p>
              </div>
            </div>
          )}

          {activeTab === 'terms' && (
            <div className="space-y-4 animate-fadeIn">
              <div>
                <h3 className="text-sm font-bold text-[#09355e] mb-1">
                  {isKm ? 'គោលការណ៍ប្រើប្រាស់ត្រឹមត្រូវ' : 'Acceptable Use Policy'}
                </h3>
                <p>
                  {isKm
                    ? 'Pinit AI ត្រូវបានផ្តល់ជូនសម្រាប់គោលបំណងការពារ និងអប់រំសន្តិសុខឌីជីថល។ អ្នកប្រើប្រាស់មិនត្រូវប្រើប្រាស់ប្រព័ន្ធនេះដើម្បីស្វែងរកចន្លោះប្រហោង ឬរៀបចំការវាយប្រហារលើប្រព័ន្ធដទៃឡើយ។'
                    : 'Pinit AI is provided solely for defensive threat verification, scam awareness, and security education. You agree not to use this service to probe for zero-day vulnerabilities, distribute unauthorized payloads, or bypass law-enforcement investigations.'}
                </p>
              </div>

              <div>
                <h3 className="text-sm font-bold text-[#09355e] mb-1">
                  {isKm ? 'កម្រិតនៃការទទួលខុសត្រូវ' : 'Disclaimer of Warranty & Liability'}
                </h3>
                <p>
                  {isKm
                    ? 'ការវិភាគត្រូវបានធ្វើឡើងដោយផ្អែកលើទិន្នន័យបច្ចេកទេស និងគំរូឆ្លាតវៃ AI។ ទោះបីជាមានភាពត្រឹមត្រូវខ្ពស់ក៏ដោយ អ្នកប្រើប្រាស់គួរតែមានការប្រុងប្រយ័ត្នផ្ទាល់ខ្លួនបន្ថែមជានិច្ច។'
                    : 'While Pinit AI achieves high detection accuracy across curated benchmarks, threat actors constantly evolve tactics. A "Safe" score indicates no known signatures or suspicious attributes were detected at scan time, but does not guarantee absolute immunity. Always exercise personal vigilance.'}
                </p>
              </div>

              <div>
                <h3 className="text-sm font-bold text-[#09355e] mb-1">
                  {isKm ? 'ការរាយការណ៍អំពីភាពមិនត្រឹមត្រូវ' : 'Responsible Feedback & False Positives'}
                </h3>
                <p>
                  {isKm
                    ? 'ប្រសិនបើអ្នកសម្គាល់ឃើញការវាយតម្លៃមិនត្រឹមត្រូវ សូមប្រើប៊ូតុងវាយតម្លៃ (មេដៃឡើង/ចុះ) ដើម្បីជួយប្រព័ន្ធកែលម្អគំរូ AI។'
                    : 'If you believe a legitimate domain or file was misclassified as suspicious, submit feedback using the Thumbs Down control on the scan card so our cybersecurity team can review and whitelist safe sources.'}
                </p>
              </div>
            </div>
          )}

          {activeTab === 'accessibility' && (
            <div className="space-y-4 animate-fadeIn">
              <div className="p-3 rounded-xl bg-sky-50 border border-sky-200 flex items-start gap-2.5">
                <Award className="w-5 h-5 text-[#0b4d82] shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-bold text-[#09355e] text-xs">
                    {isKm ? 'ស្តង់ដារ WCAG 2.1 Level AA' : 'WCAG 2.1 Level AA Conformity Statement'}
                  </h4>
                  <p className="text-[11px] text-slate-600 mt-0.5">
                    {isKm
                      ? 'Pinit AI ត្រូវបានរចនាឡើងដោយគោរពតាមស្តង់ដារភាពងាយស្រួលសម្រាប់មនុស្សគ្រប់រូប រួមទាំងអ្នកប្រើប្រាស់ក្តារចុច និងកម្មវិធីអានអេក្រង់។'
                      : 'Pinit AI strives to provide a fully accessible user experience across visual, auditory, motor, and cognitive capabilities.'}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
                <div className="p-3 rounded-lg border border-slate-200 bg-slate-50 space-y-1">
                  <div className="flex items-center gap-1.5 font-bold text-slate-800">
                    <CheckCircle className="w-4 h-4 text-emerald-600" />
                    <span>Keyboard Navigation</span>
                  </div>
                  <p className="text-slate-600">
                    Every interactive element supports full keyboard navigation (`Tab`, `Shift+Tab`, `Enter`, `Space`, `Escape`). Focus outlines are clearly highlighted with high-contrast rings.
                  </p>
                </div>

                <div className="p-3 rounded-lg border border-slate-200 bg-slate-50 space-y-1">
                  <div className="flex items-center gap-1.5 font-bold text-slate-800">
                    <CheckCircle className="w-4 h-4 text-emerald-600" />
                    <span>Screen Reader Ready</span>
                  </div>
                  <p className="text-slate-600">
                    Built with semantic HTML5 elements (`main`, `header`, `nav`, `footer`, `article`), ARIA roles, live regions for scan updates, and descriptive alt attributes.
                  </p>
                </div>

                <div className="p-3 rounded-lg border border-slate-200 bg-slate-50 space-y-1">
                  <div className="flex items-center gap-1.5 font-bold text-slate-800">
                    <CheckCircle className="w-4 h-4 text-emerald-600" />
                    <span>Color & Contrast Ratio</span>
                  </div>
                  <p className="text-slate-600">
                    All core text content meets or exceeds the 4.5:1 minimum contrast ratio requirement against background surfaces.
                  </p>
                </div>

                <div className="p-3 rounded-lg border border-slate-200 bg-slate-50 space-y-1">
                  <div className="flex items-center gap-1.5 font-bold text-slate-800">
                    <CheckCircle className="w-4 h-4 text-emerald-600" />
                    <span>Khmer Font Legibility</span>
                  </div>
                  <p className="text-slate-600">
                    Enforces `!Khmer OS Siemreap` with increased line heights (`leading-[1.85]`) to prevent vertical collisions of complex stacked Khmer diacritic vowels and subscripts.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <span className="text-[11px] text-slate-400">
            {isKm ? 'កំណែ ១.០.០ — សុវត្ថិភាពសហគមន៍' : 'Pinit Defense Engine v2.0 • Phnom Penh, Cambodia'}
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2 text-xs font-semibold rounded-xl bg-[#0b3e6e] text-white hover:bg-[#083057] transition-all cursor-pointer shadow-xs focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300"
          >
            {isKm ? 'យល់ព្រម' : 'Got it'}
          </button>
        </div>
      </div>
    </div>
  );
};
