import React from 'react';

interface PinitLogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showAiBadge?: boolean;
}

export const PinitLogo: React.FC<PinitLogoProps> = ({
  className = '',
  size = 'md',
  showAiBadge = false,
}) => {
  const heightClasses = {
    sm: 'h-6',
    md: 'h-8',
    lg: 'h-10',
    xl: 'h-12',
  };

  const hClass = heightClasses[size];

  return (
    <div className={`inline-flex items-center space-x-2 ${className}`}>
      {/* Official Pinit Logo - Cropped to fit with high-fidelity transparency */}
      <img
        src="/logo.png"
        alt="Pinit Logo"
        className={`${hClass} w-auto object-contain select-none transition-transform duration-150`}
        loading="eager"
      />

      {showAiBadge && (
        <span className="text-[11px] font-black px-1.5 py-0.5 rounded bg-sky-400 text-[#093259] tracking-wider uppercase">
          AI
        </span>
      )}
    </div>
  );
};

