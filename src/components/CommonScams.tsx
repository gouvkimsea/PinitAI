import React from 'react';
import { Smartphone, Package, Briefcase, Headphones } from 'lucide-react';
import type { Language } from '../types';

interface CommonScamsProps {
  lang: Language;
}

export const CommonScams: React.FC<CommonScamsProps> = ({ lang }) => {
  const isKm = lang === 'km';

  const scams = [
    {
      icon: <Smartphone className="w-5 h-5 text-danger" />,
      title: isKm ? 'សារ SMS បន្លំជាធនាគារ (Smishing)' : 'Bank Impersonation SMS (Smishing)',
      signal: isKm ? 'អះអាងថាគណនីត្រូវបង្កក ឬមានការដកប្រាក់មិនប្រក្រតី' : 'Claims unauthorized withdrawal or imminent account freeze',
      tip: isKm ? 'កុំចុចតំណភ្ជាប់ក្នុង SMS — ចូលតាមកម្មវិធីធនាគារផ្លូវការផ្ទាល់' : 'Never tap SMS links. Log in strictly via the official bank app.',
    },
    {
      icon: <Package className="w-5 h-5 text-suspicious" />,
      title: isKm ? 'ការបន្លំថ្លៃដឹកជញ្ជូនទំនិញ' : 'Postal / Parcel Redelivery Fees',
      signal: isKm ? 'តម្រូវឱ្យបង់ថ្លៃពន្ធ $1–$3 ដើម្បីដោះលែងកញ្ចប់ទំនិញ' : 'Asks for a small fee ($1–$3) to update a missing street address',
      tip: isKm ? 'ពិនិត្យមើលលេខកូដតាមដានលើគេហទំព័រក្រុមហ៊ុនដឹកជញ្ជូនពិតប្រាកដ' : 'Verify tracking numbers solely on official carrier portals.',
    },
    {
      icon: <Briefcase className="w-5 h-5 text-primary" />,
      title: isKm ? 'ការងារងាយប្រាក់ខែខ្ពស់តាម Telegram' : 'Telegram Task & High-Yield Jobs',
      signal: isKm ? 'សន្យាផ្តល់ $200–$800 ក្នុងមួយថ្ងៃសម្រាប់តែការចុច Like វីដេអូ' : 'Offers lucrative daily returns for simple online rating tasks',
      tip: isKm ? 'ការងារពិតប្រាកដមិនដែលតម្រូវឱ្យអ្នកដាក់លុយចូលមុនឡើយ' : 'Legitimate employers never demand upfront crypto or task deposits.',
    },
    {
      icon: <Headphones className="w-5 h-5 text-danger" />,
      title: isKm ? 'វិក្កយបត្រជំនួយបច្ចេកវិទ្យាក្លែងក្លាយ' : 'Fake Tech Support Invoices',
      signal: isKm ? 'វិក្កយបត្រក្លែងបន្លំពី Geek Squad ឬ Norton គំរាមកាត់ប្រាក់រាប់រយដុល្លារ' : 'Email stating hundreds of dollars debited with a 24-hr phone number',
      tip: isKm ? 'កុំទូរស័ព្ទទៅលេខដែលគេផ្ញើមក — ពិនិត្យគណនីធនាគារពិតប្រាកដរបស់អ្នក' : 'Never call numbers in suspicious emails; check your card app directly.',
    },
  ];

  return (
    <section className="py-12 max-w-5xl mx-auto px-4">
      <div className="text-center max-w-xl mx-auto mb-8">
        <h2 className="text-xl sm:text-2xl font-bold text-typography-headline tracking-tight mb-2">
          {isKm ? 'ល្បិចបោកប្រាស់ទូទៅដែលគួរប្រយ័ត្ន' : 'Common Scam Patterns to Watch For'}
        </h2>
        <p className="text-xs sm:text-sm text-typography-muted">
          {isKm
            ? 'ស្គាល់ពីល្បិចដែលជនបោកប្រាស់ឧស្សាហ៍ប្រើប្រាស់ ដើម្បីការពារខ្លួនអ្នក និងក្រុមគ្រួសារ។'
            : 'Familiarize yourself with the most frequent deception techniques seen today.'}
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {scams.map((item, idx) => (
          <div
            key={idx}
            className="p-4 rounded-xl bg-card border border-borderDefault shadow-subtle hover:border-slate-300 transition-standard space-y-2.5"
          >
            <div className="w-9 h-9 rounded-lg bg-surfaceInput border border-borderDefault flex items-center justify-center">
              {item.icon}
            </div>
            <h3 className="text-sm font-bold text-typography-headline">
              {item.title}
            </h3>
            <p className="text-xs text-typography-muted">
              <strong className="text-typography-body block mb-0.5">
                {isKm ? 'សញ្ញាព្រមាន៖' : 'Warning Signal:'}
              </strong>
              {item.signal}
            </p>
            <div className="pt-2 border-t border-borderDefault/60 text-[11px] text-primary font-medium">
              <strong className="block text-slate-700 mb-0.5">
                {isKm ? 'វិធីការពារ៖' : 'Best Practice:'}
              </strong>
              {item.tip}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
};
