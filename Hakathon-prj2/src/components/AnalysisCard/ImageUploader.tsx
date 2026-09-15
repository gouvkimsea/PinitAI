import React, { useState, useRef } from 'react';
import { UploadCloud, X, AlertCircle, FileCheck2, Sparkles } from 'lucide-react';
import type { Language, SampleItem } from '../../types';
import { translations } from '../../i18n/translations';
import { SAMPLE_DATA } from '../../data/samples';

interface ImageUploaderProps {
  imageFile: File | null;
  imagePreview: string | null;
  simulatedText: string;
  onImageSelected: (file: File | null, preview: string | null, textHint?: string) => void;
  lang: Language;
  disabled?: boolean;
}

export const ImageUploader: React.FC<ImageUploaderProps> = ({
  imageFile,
  imagePreview,
  simulatedText,
  onImageSelected,
  lang,
  disabled = false,
}) => {
  const t = translations[lang];
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const validateAndProcessFile = (file: File, sampleTextHint?: string) => {
    setErrorMessage(null);
    const validTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (!validTypes.includes(file.type)) {
      setErrorMessage(t.errors.unsupportedFormat);
      return;
    }

    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      setErrorMessage(t.errors.fileTooLarge);
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const previewUrl = e.target?.result as string;
      onImageSelected(
        file,
        previewUrl,
        sampleTextHint || `Uploaded image: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`
      );
    };
    reader.readAsDataURL(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (!disabled) setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (disabled) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndProcessFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndProcessFile(e.target.files[0]);
    }
  };

  const handleSelectSample = (sample: SampleItem) => {
    setErrorMessage(null);
    const canvas = document.createElement('canvas');
    canvas.width = 600;
    canvas.height = 360;
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.fillStyle = '#1E293B';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#EF4444';
      ctx.fillRect(0, 0, canvas.width, 10);
      ctx.fillStyle = '#F8FAFC';
      ctx.font = 'bold 20px sans-serif';
      ctx.fillText(sample.title, 30, 60);
      ctx.fillStyle = '#94A3B8';
      ctx.font = '14px sans-serif';
      
      const words = sample.content.split(' ');
      let line = '';
      let y = 110;
      for (const word of words) {
        const testLine = line + word + ' ';
        const metrics = ctx.measureText(testLine);
        if (metrics.width > 540 && line !== '') {
          ctx.fillText(line, 30, y);
          line = word + ' ';
          y += 26;
        } else {
          line = testLine;
        }
      }
      ctx.fillText(line, 30, y);
    }

    const previewUrl = canvas.toDataURL('image/png');
    const mockFile = new File(['mock data'], sample.imageFileName || 'sample_screenshot.png', {
      type: 'image/png',
    });

    onImageSelected(mockFile, previewUrl, sample.content);
  };

  const handleRemove = () => {
    onImageSelected(null, null, '');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const imageSamples = SAMPLE_DATA.filter((s) => s.mode === 'image');

  return (
    <div
      role="tabpanel"
      id="panel-image"
      aria-labelledby="tab-image"
      className="space-y-3"
    >
      <input
        ref={fileInputRef}
        type="file"
        id="image-analysis-file-input"
        accept="image/jpeg,image/png,image/webp"
        onChange={handleFileChange}
        disabled={disabled}
        className="hidden"
        aria-label="Upload an image"
      />

      {errorMessage && (
        <div className="flex items-center gap-2 p-3 text-xs text-danger bg-danger-light border border-danger-border rounded-lg">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {!imagePreview ? (
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !disabled && fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-8 sm:p-10 flex flex-col items-center justify-center text-center cursor-pointer transition-standard bg-surfaceInput/50 hover:bg-surfaceInput ${
            isDragOver
              ? 'border-primary bg-primary-soft/60 scale-[0.99]'
              : 'border-borderDefault hover:border-primary/50'
          } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          <div className="w-12 h-12 rounded-full bg-card border border-borderDefault shadow-subtle flex items-center justify-center text-primary mb-3">
            <UploadCloud className="w-6 h-6" />
          </div>

          <h2 className="text-base font-semibold text-typography-headline mb-1">
            {t.imageMode.title}
          </h2>
          <p className="text-xs text-typography-muted max-w-sm mb-3">
            {t.imageMode.subtitle}
          </p>

          <button
            type="button"
            disabled={disabled}
            className="px-4 py-2 text-xs font-semibold text-primary bg-card hover:bg-white border border-borderDefault rounded-lg shadow-subtle transition-standard"
          >
            {t.imageMode.browseBtn}
          </button>

          <span className="text-[11px] text-typography-muted/80 mt-3">
            {t.imageMode.formats}
          </span>
        </div>
      ) : (
        <div className="border border-borderDefault rounded-xl p-4 bg-surfaceInput/40 space-y-3">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-16 h-16 rounded-lg overflow-hidden border border-borderDefault bg-slate-900 flex-shrink-0 flex items-center justify-center">
                <img
                  src={imagePreview}
                  alt="Scam screenshot preview"
                  className="w-full h-full object-cover"
                />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-typography-headline truncate">
                  <FileCheck2 className="w-3.5 h-3.5 text-safe" />
                  <span className="truncate">{imageFile?.name || 'Uploaded Image'}</span>
                </div>
                <p className="text-[11px] text-typography-muted mt-0.5">
                  {imageFile ? `${(imageFile.size / 1024).toFixed(1)} KB` : 'Ready for AI OCR scan'}
                </p>
                <div className="flex items-center gap-2 mt-1.5">
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    disabled={disabled}
                    className="text-[11px] text-primary hover:underline font-medium cursor-pointer"
                  >
                    {t.imageMode.changeImage}
                  </button>
                  <span className="text-borderDefault">•</span>
                  <button
                    type="button"
                    onClick={handleRemove}
                    disabled={disabled}
                    className="text-[11px] text-danger hover:underline font-medium cursor-pointer"
                  >
                    {t.actions.close}
                  </button>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={handleRemove}
              disabled={disabled}
              className="p-1 rounded-md text-typography-muted hover:text-danger hover:bg-card transition-standard"
              aria-label="Remove image"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* OCR extract preview */}
          {simulatedText && (
            <div className="p-2.5 rounded-lg bg-card border border-borderDefault text-[11px] text-typography-body">
              <span className="font-semibold text-typography-headline block mb-1">
                OCR Text Extracted for Analysis:
              </span>
              <p className="line-clamp-2 text-typography-muted font-mono">{simulatedText}</p>
            </div>
          )}
        </div>
      )}

      {/* Quick Test Image Samples */}
      <div className="pt-1">
        <p className="text-[11px] font-medium text-typography-muted mb-2 flex items-center gap-1">
          <Sparkles className="w-3 h-3 text-primary" />
          <span>{t.imageMode.samplePrompt}</span>
        </p>
        <div className="flex flex-wrap gap-1.5">
          {imageSamples.map((sample) => (
            <button
              key={sample.id}
              type="button"
              disabled={disabled}
              onClick={() => handleSelectSample(sample)}
              className="text-xs px-2.5 py-1 rounded-lg border border-borderDefault bg-card hover:bg-surfaceInput text-typography-body transition-standard cursor-pointer"
            >
              <span className="font-medium">{sample.title}</span>
              <span className="ml-1 text-[10px] text-typography-muted">
                ({sample.badge})
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
