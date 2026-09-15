import React, { useState, useRef } from 'react';
import { QrCode, Upload, ShieldAlert, Sparkles } from 'lucide-react';
import type { Language, SampleItem } from '../../types';
import { translations } from '../../i18n/translations';

interface QrAnalyzerProps {
  onQrSelected: (file: File | null, rawPayload?: string) => void;
  lang: Language;
}

export const QrAnalyzer: React.FC<QrAnalyzerProps> = ({ onQrSelected, lang }) => {
  const t = translations[lang];
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [decodedPreview, setDecodedPreview] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const qrSamples: SampleItem[] = [
    {
      id: 'qr_bank',
      mode: 'qr',
      title: t.qrMode.samples.bankPhish,
      badge: 'High Risk',
      content: 'https://aba-mobile-secure-login.top/auth/verify?session=92840',
      expectedRisk: 'high_risk',
    },
    {
      id: 'qr_crypto',
      mode: 'qr',
      title: t.qrMode.samples.cryptoQuish,
      badge: 'High Risk',
      content: 'https://telegram-airdrop-usdt.xyz/claim?ref=bonus500',
      expectedRisk: 'high_risk',
    },
    {
      id: 'qr_safe',
      mode: 'qr',
      title: t.qrMode.samples.safeMenu,
      badge: 'Likely Safe',
      content: 'https://www.browncoffee.com.kh/menu/beverages',
      expectedRisk: 'safe',
    },
  ];

  const handleFile = (file: File) => {
    setSelectedFile(file);
    const url = URL.createObjectURL(file);
    setPreviewUrl(url);
    setDecodedPreview(null);
    onQrSelected(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handleSelectSample = (sample: SampleItem) => {
    setSelectedFile(null);
    setPreviewUrl(null);
    setDecodedPreview(sample.content);
    onQrSelected(null, sample.content);
  };

  return (
    <div className="space-y-4">
      {/* Upload Drag & Drop Area */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-standard ${
          isDragging
            ? 'border-primary bg-primary-light/50 scale-[1.01]'
            : selectedFile || decodedPreview
            ? 'border-borderDefault bg-surfaceInput/40'
            : 'border-borderDefault hover:border-primary/50 hover:bg-card/50'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
          accept="image/png, image/jpeg, image/webp"
          className="hidden"
        />

        {previewUrl ? (
          <div className="flex flex-col items-center gap-3">
            <div className="relative w-32 h-32 rounded-lg overflow-hidden border border-borderDefault bg-white shadow-sm p-1">
              <img src={previewUrl} alt="QR Preview" className="w-full h-full object-contain" />
            </div>
            <div className="text-center">
              <p className="text-xs font-semibold text-typography-headline">{selectedFile?.name}</p>
              <p className="text-[11px] text-typography-muted">
                {(Number(selectedFile?.size) / 1024).toFixed(1)} KB • Click or drop another image to replace
              </p>
            </div>
          </div>
        ) : decodedPreview ? (
          <div className="flex flex-col items-center gap-2 py-3">
            <div className="w-12 h-12 rounded-xl bg-primary-light flex items-center justify-center text-primary">
              <QrCode className="w-6 h-6" />
            </div>
            <span className="text-xs font-semibold text-typography-headline">
              {t.qrMode.decodedTarget}
            </span>
            <code className="px-3 py-1 rounded bg-black/5 dark:bg-white/10 font-mono text-xs text-primary max-w-md truncate">
              {decodedPreview}
            </code>
            <p className="text-[11px] text-typography-muted">Sample QR code payload active. Click 'Analyze Now' below.</p>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-3 py-4">
            <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center text-primary">
              <QrCode className="w-6 h-6" />
            </div>
            <div>
              <p className="text-sm font-semibold text-typography-headline">{t.qrMode.title}</p>
              <p className="text-xs text-typography-muted mt-1">{t.qrMode.subtitle}</p>
            </div>
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-card border border-borderDefault text-xs font-medium text-typography-headline shadow-xs hover:bg-surfaceInput">
              <Upload className="w-3.5 h-3.5" />
              <span>{t.qrMode.browseBtn}</span>
            </span>
            <p className="text-[10px] text-typography-muted">{t.qrMode.formats}</p>
          </div>
        )}
      </div>

      {/* Safety Notice Banner */}
      <div className="p-3 rounded-lg bg-primary-light/40 border border-primary/20 flex items-start gap-2.5 text-xs text-typography-body">
        <ShieldAlert className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
        <p className="leading-relaxed text-[11px]">{t.qrMode.caution}</p>
      </div>

      {/* Samples prompt */}
      <div className="space-y-2">
        <span className="text-xs text-typography-muted font-medium flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-primary" />
          <span>{t.qrMode.samplePrompt}</span>
        </span>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {qrSamples.map((sample) => (
            <button
              key={sample.id}
              type="button"
              onClick={() => handleSelectSample(sample)}
              className="p-2.5 rounded-lg border border-borderDefault bg-card hover:bg-surfaceInput hover:border-primary/40 text-left transition-standard flex flex-col justify-between gap-1 group cursor-pointer"
            >
              <div className="flex items-center justify-between gap-1">
                <span className="text-xs font-semibold text-typography-headline group-hover:text-primary transition-colors truncate">
                  {sample.title}
                </span>
                <span
                  className={`text-[9px] uppercase px-1.5 py-0.5 rounded font-bold ${
                    sample.expectedRisk === 'high_risk'
                      ? 'bg-danger-light text-danger-dark'
                      : 'bg-safe-light text-safe-dark'
                  }`}
                >
                  {sample.badge}
                </span>
              </div>
              <p className="text-[10px] font-mono text-typography-muted truncate">
                {sample.content}
              </p>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
