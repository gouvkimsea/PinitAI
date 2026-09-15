import React, { useState } from 'react';
import { X, Flag, CheckCircle, Send, Loader2, AlertCircle } from 'lucide-react';
import type { Language } from '../../types';
import { api } from '../../services/api';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  prefillSnippet?: string;
  lang: Language;
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  prefillSnippet = '',
  lang,
}) => {
  const isKm = lang === 'km';
  const [scamType, setScamType] = useState('phishing');
  const [description, setDescription] = useState(prefillSnippet);
  const [submitted, setSubmitted] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMessage(null);

    try {
      await api.submitReport({
        scamType,
        description,
        target: prefillSnippet.startsWith('http') ? prefillSnippet : undefined,
      });
      setSubmitted(true);
      setTimeout(() => {
        setSubmitted(false);
        onClose();
      }, 2000);
    } catch (err) {
      setErrorMessage((err as Error).message || 'Failed to submit report.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="report-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-fadeIn"
    >
      <div className="w-full max-w-lg bg-card rounded-2xl border border-borderDefault shadow-elevated p-6 relative">
        <button
          type="button"
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-typography-muted hover:text-typography-headline rounded-lg hover:bg-surfaceInput transition-standard"
          aria-label="Close modal"
        >
          <X className="w-5 h-5" />
        </button>

        {submitted ? (
          <div className="py-8 text-center space-y-3">
            <div className="w-14 h-14 mx-auto rounded-full bg-safe-light border border-safe-border flex items-center justify-center text-safe">
              <CheckCircle className="w-8 h-8" />
            </div>
            <h3 className="text-lg font-bold text-typography-headline">
              {isKm ? 'បានទទួលរបាយការណ៍ជោគជ័យ!' : 'Report Submitted!'}
            </h3>
            <p className="text-xs text-typography-muted max-w-sm mx-auto">
              {isKm
                ? 'អរគុណសម្រាប់ការជួយការពារសហគមន៍។ ព័ត៌មាននេះនឹងត្រូវបានផ្ទៀងផ្ទាត់ និងបញ្ចូលក្នុងទិន្នន័យព្រមានជាសកល។'
                : 'Thank you for contributing to global cyber safety. Threat intelligence feeds have been updated.'}
            </p>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-xl bg-danger-light border border-danger-border flex items-center justify-center text-danger">
                <Flag className="w-5 h-5" />
              </div>
              <div>
                <h2 id="report-modal-title" className="text-base font-bold text-typography-headline">
                  {isKm ? 'រាយការណ៍ការបោកប្រាស់នេះ' : 'Report Suspicious Threat'}
                </h2>
                <p className="text-xs text-typography-muted">
                  {isKm
                    ? 'ជួយការពារអ្នកដទៃពីការចាញ់បោកជនខិលខូច'
                    : 'Help protect other users and enrich public threat registries.'}
                </p>
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-typography-headline">
                {isKm ? 'ប្រភេទនៃការបោកប្រាស់' : 'Scam Category'}
              </label>
              <select
                value={scamType}
                onChange={(e) => setScamType(e.target.value)}
                className="w-full p-2.5 bg-surfaceInput border border-borderDefault rounded-lg text-xs font-medium text-typography-headline focus:ring-2 focus:ring-primary/20 focus:outline-none"
              >
                <option value="phishing">{isKm ? 'សារក្លែងបន្លំ ឬតំណបន្លំ (Phishing)' : 'Phishing / Fake Login'}</option>
                <option value="impersonation">{isKm ? 'ការក្លែងបន្លំជាស្ថាប័ន ឬធនាគារ' : 'Bank or Brand Impersonation'}</option>
                <option value="crypto">{isKm ? 'ការបោកប្រាស់ប្រាក់កាស ឬរូបិយប័ណ្ណគ្រីបតូ' : 'Crypto / Investment Fraud'}</option>
                <option value="job">{isKm ? 'ការបោកប្រាស់ការងារតាម Telegram' : 'Fake Telegram / Remote Job'}</option>
                <option value="other">{isKm ? 'ផ្សេងៗ' : 'Other Suspicious Activity'}</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-typography-headline">
                {isKm ? 'ព័ត៌មានលម្អិត ឬតំណភ្ជាប់' : 'Evidence / Content Snippet'}
              </label>
              <textarea
                rows={4}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder={isKm ? 'បិទភ្ជាប់ព័ត៌មានលម្អិតនៅទីនេះ...' : 'Paste message snippet, sender phone, or link...'}
                required
                className="w-full p-3 bg-surfaceInput border border-borderDefault rounded-lg text-xs font-mono text-typography-headline focus:ring-2 focus:ring-primary/20 focus:outline-none resize-none"
              />
            </div>

            {errorMessage && (
              <div className="p-2.5 rounded-lg bg-danger-light border border-danger-border flex items-center gap-2 text-xs text-danger">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={onClose}
                disabled={isLoading}
                className="px-4 py-2 text-xs font-medium text-typography-muted hover:text-typography-headline rounded-lg border border-borderDefault disabled:opacity-50"
              >
                {isKm ? 'បោះបង់' : 'Cancel'}
              </button>
              <button
                type="submit"
                disabled={isLoading}
                className="px-5 py-2 text-xs font-semibold text-white bg-danger hover:bg-danger-dark rounded-lg flex items-center gap-1.5 transition-standard disabled:opacity-60"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>{isKm ? 'កំពុងផ្ញើ...' : 'Submitting...'}</span>
                  </>
                ) : (
                  <>
                    <Send className="w-3.5 h-3.5" />
                    <span>{isKm ? 'ដាក់ស្នើរបាយការណ៍' : 'Submit Threat Report'}</span>
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
