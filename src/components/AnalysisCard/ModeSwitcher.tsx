import React from 'react';
import { FileText, Image as ImageIcon, Link2, Paperclip, QrCode } from 'lucide-react';
import type { AnalysisMode, Language } from '../../types';
import { translations } from '../../i18n/translations';

interface ModeSwitcherProps {
  activeMode: AnalysisMode;
  onSelectMode: (mode: AnalysisMode) => void;
  lang: Language;
  disabled?: boolean;
}

export const ModeSwitcher: React.FC<ModeSwitcherProps> = ({
  activeMode,
  onSelectMode,
  lang,
  disabled = false,
}) => {
  const t = translations[lang];

  const tabs: { id: AnalysisMode; label: string; icon: React.ReactNode }[] = [
    {
      id: 'text',
      label: t.modes.text,
      icon: <FileText className="w-4 h-4" aria-hidden="true" />,
    },
    {
      id: 'url',
      label: t.modes.url,
      icon: <Link2 className="w-4 h-4" aria-hidden="true" />,
    },
    {
      id: 'qr',
      label: t.modes.qr,
      icon: <QrCode className="w-4 h-4" aria-hidden="true" />,
    },
    {
      id: 'file',
      label: t.modes.file,
      icon: <Paperclip className="w-4 h-4" aria-hidden="true" />,
    },
    {
      id: 'image',
      label: t.modes.image,
      icon: <ImageIcon className="w-4 h-4" aria-hidden="true" />,
    },
  ];

  return (
    <div
      role="tablist"
      aria-label="Analysis Mode Selector"
      className="grid grid-cols-2 sm:grid-cols-5 p-1.5 bg-surfaceInput/80 rounded-xl border border-borderDefault gap-1"
    >
      {tabs.map((tab) => {
        const isActive = activeMode === tab.id;
        return (
          <button
            key={tab.id}
            role="tab"
            type="button"
            id={`tab-${tab.id}`}
            aria-selected={isActive}
            aria-controls={`panel-${tab.id}`}
            disabled={disabled}
            onClick={() => onSelectMode(tab.id)}
            className={`flex items-center justify-center gap-1.5 py-2.5 px-2.5 rounded-lg text-xs sm:text-sm font-medium transition-standard select-none cursor-pointer focus-visible:ring-2 focus-visible:ring-primary ${
              isActive
                ? 'bg-primary text-white shadow-subtle hover:bg-primary-hover font-semibold'
                : 'bg-transparent text-typography-muted hover:text-typography-body hover:bg-card/70'
            } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        );
      })}
    </div>
  );
};
