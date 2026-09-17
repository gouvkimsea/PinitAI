import React, { useState } from 'react';
import { Check, Sparkles } from 'lucide-react';

interface PricingSectionProps {
  onSelectPlan: (planName: string) => void;
}

export const PricingSection: React.FC<PricingSectionProps> = ({ onSelectPlan }) => {
  const [annualBilling, setAnnualBilling] = useState(false);

  const plans = [
    {
      id: 'free',
      badge: 'FREE',
      title: 'Free',
      subtitle: 'For individuals who want basic protection',
      monthlyPrice: '$0',
      annualPrice: '$0',
      period: 'forever free',
      featured: false,
      features: [
        '10 real-time threat scans per day',
        'Standard file extension & virus inspection',
        'Basic scam risk score (0-100)',
        'URL phishing database check (40+ feeds)',
      ],
      ctaText: 'Get Started Free',
      ctaStyle: 'bg-white hover:bg-slate-50 text-[#0b4d82] border-2 border-[#0b4d82]',
    },
    {
      id: 'pro',
      badge: 'PRO',
      title: 'Pro',
      subtitle: 'For power users, freelancers & professionals',
      monthlyPrice: '$5',
      annualPrice: '$4',
      period: 'per month',
      featured: true, // In screenshot, PRO card has solid dark blue background!
      features: [
        'Unlimited real-time scans across all media',
        'Deep AI heuristic SMS & email scam dissection',
        'QR Code quarantine sandbox & redirect preview',
        'Advanced executable & macro virus disassembly',
        'Sub-second threat response time (< 1.2s)',
        'Chrome & Firefox browser protection extension',
      ],
      ctaText: 'Upgrade to Pro',
      ctaStyle: 'bg-sky-500 hover:bg-sky-400 text-white font-bold shadow-md hover:shadow-lg',
    },
    {
      id: 'team',
      badge: 'TEAM',
      title: 'Team',
      subtitle: 'For teams, agencies & growing organizations',
      monthlyPrice: '$15',
      annualPrice: '$12',
      period: 'per month (up to 10 seats)',
      featured: false,
      features: [
        'Everything in Pro for entire organization',
        'Centralized security audit log & admin console',
        'API access (15,000 automated queries / month)',
        'Automated Slack & Microsoft Teams phishing bot',
        'Domain spoofing monitoring for your brand',
        'Priority 24/7 cybersecurity SLA support',
      ],
      ctaText: 'Start Team Trial',
      ctaStyle: 'bg-white hover:bg-slate-50 text-[#0b4d82] border-2 border-[#0b4d82]',
    },
  ];

  return (
    <section id="pricing" className="max-w-6xl mx-auto px-4 sm:px-6 pt-12 pb-20" aria-label="Subscription Plans">
      <div className="text-center mb-10">
        {/* Exact header from screenshot: UPGRADE YOUR PLAN */}
        <h2 className="text-2xl sm:text-3xl md:text-4xl font-extrabold text-[#09355e] tracking-tight uppercase">
          UPGRADE YOUR PLAN
        </h2>
        <p className="mt-2 text-sm sm:text-base text-slate-600 max-w-xl mx-auto">
          Choose the right security shield for your links, documents, messages, and team communications.
        </p>

        {/* Billing frequency toggle */}
        <div className="mt-6 inline-flex items-center bg-slate-200/70 p-1 rounded-full text-xs font-semibold text-slate-700">
          <button
            type="button"
            onClick={() => setAnnualBilling(false)}
            className={`px-4 py-1.5 rounded-full transition-all ${
              !annualBilling ? 'bg-white text-[#09355e] shadow-xs font-bold' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Monthly
          </button>
          <button
            type="button"
            onClick={() => setAnnualBilling(true)}
            className={`px-4 py-1.5 rounded-full transition-all flex items-center space-x-1 ${
              annualBilling ? 'bg-white text-[#09355e] shadow-xs font-bold' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <span>Annual</span>
            <span className="text-[10px] bg-emerald-100 text-emerald-800 font-bold px-1.5 py-0.2 rounded-full">
              Save 20%
            </span>
          </button>
        </div>
      </div>

      {/* 3 Pricing Cards matching Screenshot Layout */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 sm:gap-8 items-stretch">
        {plans.map((plan) => {
          const isFeatured = plan.featured;
          return (
            <article
              key={plan.id}
              className={`rounded-3xl transition-all duration-200 flex flex-col justify-between p-6 sm:p-8 relative ${
                isFeatured
                  ? 'bg-[#0b4272] text-white shadow-xl ring-2 ring-sky-400 md:-translate-y-2'
                  : 'bg-white text-slate-900 border border-slate-300/90 shadow-xs hover:shadow-md'
              }`}
            >
              {/* Most Popular Badge on PRO */}
              {isFeatured && (
                <div className="absolute -top-3.5 left-1/2 -translate-x-1/2 bg-sky-400 text-[#09355e] text-xs font-extrabold px-3 py-1 rounded-full uppercase tracking-wider shadow-sm flex items-center space-x-1">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>RECOMMENDED</span>
                </div>
              )}

              <div>
                {/* Header Badge Pill matching Screenshot */}
                <div className="flex items-center justify-between mb-4">
                  <span
                    className={`inline-block text-xs font-extrabold px-3 py-1 rounded-md tracking-wider ${
                      isFeatured
                        ? 'bg-white/20 text-white border border-white/30'
                        : 'bg-slate-100 text-slate-800 border border-slate-200'
                    }`}
                  >
                    {plan.badge}
                  </span>
                </div>

                {/* Subtitle from Screenshot */}
                <p className={`text-xs sm:text-sm mb-6 ${isFeatured ? 'text-sky-100' : 'text-slate-600'}`}>
                  {plan.subtitle}
                </p>

                {/* Price Display */}
                <div className="mb-6">
                  <div className="flex items-baseline space-x-1">
                    <span className="text-3xl sm:text-4xl font-extrabold tracking-tight">
                      {annualBilling ? plan.annualPrice : plan.monthlyPrice}
                    </span>
                    <span className={`text-xs ${isFeatured ? 'text-sky-200' : 'text-slate-500'}`}>
                      / {plan.period}
                    </span>
                  </div>
                </div>

                {/* Feature List */}
                <div className={`space-y-3 pt-6 border-t ${isFeatured ? 'border-white/20' : 'border-slate-100'}`}>
                  <span className={`text-xs font-bold uppercase tracking-wider block ${
                    isFeatured ? 'text-sky-200' : 'text-slate-500'
                  }`}>
                    What is included:
                  </span>
                  <ul className="space-y-2.5">
                    {plan.features.map((feature, i) => (
                      <li key={i} className="flex items-start space-x-2.5 text-xs sm:text-sm">
                        <div
                          className={`mt-0.5 rounded-full p-0.5 shrink-0 ${
                            isFeatured ? 'bg-sky-400/20 text-sky-300' : 'bg-sky-100 text-[#0b4d82]'
                          }`}
                        >
                          <Check className="w-3.5 h-3.5 stroke-[2.5]" aria-hidden="true" />
                        </div>
                        <span className={isFeatured ? 'text-sky-50' : 'text-slate-700'}>
                          {feature}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Action Button */}
              <div className="mt-8 pt-4">
                <button
                  type="button"
                  onClick={() => onSelectPlan(plan.title)}
                  className={`w-full py-3 px-4 rounded-xl text-xs sm:text-sm font-semibold transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 ${
                    isFeatured
                      ? 'focus-visible:ring-white focus-visible:ring-offset-[#0b4272]'
                      : 'focus-visible:ring-[#0b4d82] focus-visible:ring-offset-white'
                  } ${plan.ctaStyle}`}
                >
                  {plan.ctaText}
                </button>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
};
