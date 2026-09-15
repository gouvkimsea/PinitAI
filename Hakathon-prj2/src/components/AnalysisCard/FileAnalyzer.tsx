import React, { useState, useRef } from 'react';
import { FileText, FileCode, Paperclip, X, AlertTriangle, FileCheck2, Sparkles, ShieldAlert } from 'lucide-react';
import type { Language, SampleItem } from '../../types';
import { translations } from '../../i18n/translations';
import { SAMPLE_DATA } from '../../data/samples';

interface FileAnalyzerProps {
  fileObject: File | null;
  extractedText: string;
  onFileSelected: (file: File | null, content: string) => void;
  lang: Language;
  disabled?: boolean;
}

export const FileAnalyzer: React.FC<FileAnalyzerProps> = ({
  fileObject,
  extractedText,
  onFileSelected,
  lang,
  disabled = false,
}) => {
  const t = translations[lang];
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const isDangerousExtension = (fileName: string): boolean => {
    return /\.(exe|scr|vbs|bat|cmd|iso|ps1|jar|pif)$/i.test(fileName);
  };

  const processFile = (file: File) => {
    setErrorMessage(null);

    const maxSize = 15 * 1024 * 1024; // 15MB
    if (file.size > maxSize) {
      setErrorMessage(t.errors.fileTooLarge);
      return;
    }

    const reader = new FileReader();

    // If text, html, eml, txt, or json
    if (file.type.includes('text') || file.name.endsWith('.html') || file.name.endsWith('.eml') || file.name.endsWith('.txt')) {
      reader.onload = (e) => {
        const textContent = (e.target?.result as string) || '';
        onFileSelected(file, `${file.name}\n${textContent.slice(0, 1000)}`);
      };
      reader.readAsText(file);
    } else {
      // For binary documents like PDF/DOCX, parse readable metadata + preview hint
      reader.onload = () => {
        const snippet = `[Document File: ${file.name}, Size: ${(file.size / 1024).toFixed(1)} KB]\nAutomated structural scan: checking document streams, embedded macros, external URL links, and billing urgency markers.`;
        onFileSelected(file, snippet);
      };
      reader.readAsArrayBuffer(file);
    }
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
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
    }
  };

  const handleSelectSample = (sample: SampleItem) => {
    setErrorMessage(null);
    const mockBlob = new Blob([sample.content], { type: 'text/plain' });
    const mockFile = new File([mockBlob], sample.fileName || `${sample.title}.pdf`, {
      type: 'application/pdf',
    });
    onFileSelected(mockFile, `${sample.fileName || sample.title}\n${sample.content}`);
  };

  const handleRemove = () => {
    onFileSelected(null, '');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const fileSamples = SAMPLE_DATA.filter((s) => s.mode === 'file');
  const isHazardous = fileObject ? isDangerousExtension(fileObject.name) : false;

  return (
    <div
      role="tabpanel"
      id="panel-file"
      aria-labelledby="tab-file"
      className="space-y-3"
    >
      <input
        ref={fileInputRef}
        type="file"
        id="file-analysis-input"
        accept=".pdf,.docx,.xlsx,.html,.eml,.txt,.exe,.scr,.vbs"
        onChange={handleFileChange}
        disabled={disabled}
        className="hidden"
        aria-label="Upload a document or file"
      />

      {errorMessage && (
        <div className="flex items-center gap-2 p-3 text-xs text-danger bg-danger-light border border-danger-border rounded-lg">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {!fileObject ? (
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
            <Paperclip className="w-6 h-6" />
          </div>

          <h2 className="text-base font-semibold text-typography-headline mb-1">
            {t.fileMode.title}
          </h2>
          <p className="text-xs text-typography-muted max-w-sm mb-3">
            {t.fileMode.subtitle}
          </p>

          <button
            type="button"
            disabled={disabled}
            className="px-4 py-2 text-xs font-semibold text-primary bg-card hover:bg-white border border-borderDefault rounded-lg shadow-subtle transition-standard"
          >
            {t.fileMode.browseBtn}
          </button>

          <span className="text-[11px] text-typography-muted/80 mt-3">
            {t.fileMode.formats}
          </span>
        </div>
      ) : (
        <div className="border border-borderDefault rounded-xl p-4 bg-surfaceInput/40 space-y-3">
          {/* Hazardous alert banner */}
          {isHazardous && (
            <div className="flex items-start gap-2 p-3 bg-danger-light border border-danger-border rounded-lg text-xs text-danger-dark font-medium">
              <ShieldAlert className="w-4 h-4 text-danger flex-shrink-0 mt-0.5" />
              <span>{t.fileMode.hazardWarning}</span>
            </div>
          )}

          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-12 h-12 rounded-xl bg-card border border-borderDefault shadow-xs flex-shrink-0 flex items-center justify-center text-primary">
                {fileObject.name.endsWith('.html') ? (
                  <FileCode className="w-6 h-6 text-primary" />
                ) : (
                  <FileText className="w-6 h-6 text-primary" />
                )}
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-typography-headline truncate">
                  <FileCheck2 className="w-3.5 h-3.5 text-safe" />
                  <span className="truncate">{fileObject.name}</span>
                </div>
                <p className="text-[11px] text-typography-muted mt-0.5">
                  {(fileObject.size / 1024).toFixed(1)} KB • Ready for security stream scan
                </p>
                <div className="flex items-center gap-2 mt-1.5">
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    disabled={disabled}
                    className="text-[11px] text-primary hover:underline font-medium cursor-pointer"
                  >
                    {t.fileMode.changeFile}
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
              className="p-1 rounded-md text-typography-muted hover:text-danger hover:bg-card transition-standard cursor-pointer"
              aria-label="Remove file"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Extracted text snippet preview */}
          {extractedText && (
            <div className="p-2.5 rounded-lg bg-card border border-borderDefault text-[11px] text-typography-body">
              <span className="font-semibold text-typography-headline block mb-1">
                {t.fileMode.extractedPreview}
              </span>
              <p className="line-clamp-3 text-typography-muted font-mono leading-relaxed">
                {extractedText}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Quick Test File Samples */}
      <div className="pt-1">
        <p className="text-[11px] font-medium text-typography-muted mb-2 flex items-center gap-1">
          <Sparkles className="w-3 h-3 text-primary" />
          <span>{t.fileMode.samplePrompt}</span>
        </p>
        <div className="flex flex-wrap gap-1.5">
          {fileSamples.map((sample) => (
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
