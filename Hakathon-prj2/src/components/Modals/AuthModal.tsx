import React, { useState } from 'react';
import { X, Lock, Mail, ArrowRight, Check, AlertCircle } from 'lucide-react';
import type { Language } from '../../types';
import { api } from '../../services/api';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
  onSuccess?: () => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, lang, onSuccess }) => {
  const isKm = lang === 'km';
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [signedIn, setSignedIn] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setIsSubmitting(true);

    try {
      if (isLogin) {
        await api.login(email, password);
      } else {
        await api.register(email, password);
      }
      setSignedIn(true);
      onSuccess?.();
      setTimeout(() => {
        setSignedIn(false);
        onClose();
      }, 1200);
    } catch (err: any) {
      setAuthError(err.message || (isKm ? 'ការផ្ទៀងផ្ទាត់មិនជោគជ័យ' : 'Authentication failed.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-sm animate-fadeIn"
    >
      <div className="w-full max-w-md bg-card rounded-2xl border border-borderDefault shadow-elevated p-6 relative">
        <button
          type="button"
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-typography-muted hover:text-typography-headline rounded-lg hover:bg-surfaceInput transition-standard"
          aria-label="Close modal"
        >
          <X className="w-5 h-5" />
        </button>

        {signedIn ? (
          <div className="py-8 text-center space-y-3">
            <div className="w-14 h-14 mx-auto rounded-full bg-safe-light border border-safe-border flex items-center justify-center text-safe">
              <Check className="w-8 h-8" />
            </div>
            <h3 className="text-lg font-bold text-typography-headline">
              {isKm ? 'ចូលគណនីជោគជ័យ!' : 'Welcome Back!'}
            </h3>
            <p className="text-xs text-typography-muted">
              {isKm ? 'គណនីរបស់អ្នកត្រូវបានភ្ជាប់ដោយជោគជ័យ។' : 'Your session is active. You can now track your scan history.'}
            </p>
          </div>
        ) : (
          <form onSubmit={handleAuthSubmit} className="space-y-4">
            <div className="space-y-1">
              <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-primary-soft text-primary text-[11px] font-semibold mb-1">
                <Lock className="w-3 h-3" />
                <span>{isKm ? 'ស្រេចចិត្ត' : 'Optional Account'}</span>
              </div>
              <h2 id="auth-modal-title" className="text-xl font-bold text-typography-headline">
                {isLogin ? (isKm ? 'ចូលគណនី' : 'Welcome back') : (isKm ? 'បង្កើតគណនីថ្មី' : 'Create an Account')}
              </h2>
              <p className="text-xs text-typography-muted">
                {isKm
                  ? 'ការស្កេនគឺឥតគិតថ្លៃ និងមិនចាំបាច់មានគណនីឡើយ។ បង្កើតគណនីប្រសិនបើអ្នកចង់រក្សាប្រវត្តិស្កេន។'
                  : 'Scanning is 100% free without an account. Sign in if you want to store personal scan records.'}
              </p>
            </div>

            {authError && (
              <div role="alert" className="p-2.5 rounded-lg bg-danger-light border border-danger-border flex items-center gap-2 text-danger-dark text-xs">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{authError}</span>
              </div>
            )}

            <div className="space-y-3 pt-2">
              <div>
                <label className="text-xs font-semibold text-typography-headline block mb-1">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-typography-muted absolute left-3 top-3" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="user@example.com"
                    className="w-full pl-9 pr-3 py-2.5 bg-surfaceInput border border-borderDefault rounded-lg text-xs text-typography-headline focus:ring-2 focus:ring-primary/20 focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-semibold text-typography-headline block mb-1">
                  Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-typography-muted absolute left-3 top-3" />
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full pl-9 pr-3 py-2.5 bg-surfaceInput border border-borderDefault rounded-lg text-xs text-typography-headline focus:ring-2 focus:ring-primary/20 focus:outline-none"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2.5 rounded-lg bg-primary hover:bg-primary-hover disabled:opacity-50 text-white font-semibold text-xs transition-standard flex items-center justify-center gap-1.5 shadow-sm"
              >
                <span>{isSubmitting ? (isKm ? 'កំពុងដំណើរការ...' : 'Authenticating...') : isLogin ? (isKm ? 'ចូលប្រើ' : 'Sign In') : (isKm ? 'ចុះឈ្មោះ' : 'Sign Up')}</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => setIsLogin(!isLogin)}
                  className="text-xs text-primary hover:underline font-medium"
                >
                  {isLogin
                    ? (isKm ? 'មិនទាន់មានគណនី? ចុះឈ្មោះទីនេះ' : "Don't have an account? Sign up")
                    : (isKm ? 'មានគណនីរួចហើយ? ចូលប្រើ' : 'Already have an account? Sign in')}
                </button>
              </div>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
