import React, { useState, useEffect } from 'react';
import { X, Mail, Lock, User, ArrowRight, CheckCircle2 } from 'lucide-react';
import { PinitLogo } from './PinitLogo';

interface AuthModalProps {
  isOpen: boolean;
  initialMode: 'login' | 'signup';
  planName?: string | null;
  onClose: () => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  initialMode,
  planName,
  onClose,
}) => {
  const [mode, setMode] = useState<'login' | 'signup'>(initialMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [submitted, setSubmitted] = useState(false);

  useEffect(() => {
    setMode(initialMode);
    setSubmitted(false);
  }, [initialMode, isOpen]);

  // Handle escape key
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

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;
    setSubmitted(true);
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs animate-fadeIn"
    >
      <div 
        className="bg-white w-full max-w-md rounded-2xl shadow-2xl border border-slate-200 overflow-hidden relative"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header Bar */}
        <div className="bg-[#0b3e6e] text-white p-5 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <PinitLogo size="sm" />
            <div className="border-l border-sky-600/60 pl-3">
              <h2 id="auth-modal-title" className="text-sm font-bold text-white">
                {mode === 'login' ? 'Sign In' : 'Create Account'}
              </h2>
              {planName && (
                <p className="text-[11px] text-sky-200">
                  Selected: <span className="font-semibold text-white">{planName}</span>
                </p>
              )}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-300 hover:text-white p-1 rounded-lg hover:bg-white/10 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6">
          {submitted ? (
            <div className="text-center py-6 space-y-3">
              <div className="w-14 h-14 bg-emerald-100 text-emerald-600 rounded-full flex items-center justify-center mx-auto">
                <CheckCircle2 className="w-8 h-8" />
              </div>
              <h3 className="text-lg font-bold text-slate-800">
                {mode === 'login' ? 'Welcome back!' : 'Account registered successfully!'}
              </h3>
              <p className="text-xs text-slate-600 max-w-xs mx-auto">
                You are now protected by Pinit threat intelligence database. Your session is active.
              </p>
              <button
                type="button"
                onClick={onClose}
                className="mt-4 px-6 py-2.5 bg-[#0b3e6e] text-white text-xs font-semibold rounded-xl hover:bg-[#083057] transition-all"
              >
                Continue to Dashboard
              </button>
            </div>
          ) : (
            <>
              {/* Mode Switcher */}
              <div className="flex border-b border-slate-200 mb-5">
                <button
                  type="button"
                  onClick={() => setMode('login')}
                  className={`flex-1 pb-2.5 text-xs sm:text-sm font-semibold border-b-2 transition-all ${
                    mode === 'login'
                      ? 'border-[#0b3e6e] text-[#0b3e6e]'
                      : 'border-transparent text-slate-500 hover:text-slate-800'
                  }`}
                >
                  Log In
                </button>
                <button
                  type="button"
                  onClick={() => setMode('signup')}
                  className={`flex-1 pb-2.5 text-xs sm:text-sm font-semibold border-b-2 transition-all ${
                    mode === 'signup'
                      ? 'border-[#0b3e6e] text-[#0b3e6e]'
                      : 'border-transparent text-slate-500 hover:text-slate-800'
                  }`}
                >
                  Sign Up
                </button>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                {mode === 'signup' && (
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1" htmlFor="auth-name">
                      Full Name
                    </label>
                    <div className="relative">
                      <User className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                      <input
                        id="auth-name"
                        type="text"
                        required
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="Alex Morgan"
                        className="w-full pl-9 pr-3 py-2 text-xs sm:text-sm border border-slate-300 rounded-xl focus:border-[#0b3e6e] focus:ring-2 focus:ring-[#0b3e6e]/20 outline-none text-slate-800"
                      />
                    </div>
                  </div>
                )}

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1" htmlFor="auth-email">
                    Email address
                  </label>
                  <div className="relative">
                    <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                    <input
                      id="auth-email"
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="alex@company.com"
                      className="w-full pl-9 pr-3 py-2 text-xs sm:text-sm border border-slate-300 rounded-xl focus:border-[#0b3e6e] focus:ring-2 focus:ring-[#0b3e6e]/20 outline-none text-slate-800"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1" htmlFor="auth-password">
                    Password
                  </label>
                  <div className="relative">
                    <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                    <input
                      id="auth-password"
                      type="password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••••••"
                      className="w-full pl-9 pr-3 py-2 text-xs sm:text-sm border border-slate-300 rounded-xl focus:border-[#0b3e6e] focus:ring-2 focus:ring-[#0b3e6e]/20 outline-none text-slate-800"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  className="w-full mt-2 py-2.5 px-4 bg-[#0b3e6e] hover:bg-[#093259] text-white text-xs sm:text-sm font-semibold rounded-xl transition-colors flex items-center justify-center space-x-1 shadow-sm"
                >
                  <span>{mode === 'login' ? 'Sign In' : 'Create Account'}</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </form>

              <div className="mt-4 pt-4 border-t border-slate-100 text-center">
                <p className="text-[11px] text-slate-500">
                  By continuing, you agree to Pinit’s Threat Intelligence Terms of Service & Privacy Policy.
                </p>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
