import React, { useState } from 'react';
import { AlertCircle } from 'lucide-react';
import type { AnalysisMode, AnalysisResult, Language, RiskLevel } from '../../types';
import { translations } from '../../i18n/translations';
import { ModeSwitcher } from './ModeSwitcher';
import { TextAnalyzer } from './TextAnalyzer';
import { ImageUploader } from './ImageUploader';
import { UrlAnalyzer } from './UrlAnalyzer';
import { FileAnalyzer } from './FileAnalyzer';
import { QrAnalyzer } from './QrAnalyzer';
import { AnalyzeButton } from './AnalyzeButton';
import { LoadingState } from '../LoadingState';
import { ResultCard } from '../ResultCard/ResultCard';
import { analyzeContent } from '../../engine/scamDetector';
import { api, API_BASE_URL } from '../../services/api';

interface AnalysisCardProps {
  lang: Language;
  onOpenReportScam: (prefillData?: string) => void;
}

export const AnalysisCard: React.FC<AnalysisCardProps> = ({
  lang,
  onOpenReportScam,
}) => {
  const t = translations[lang];

  // State
  const [activeMode, setActiveMode] = useState<AnalysisMode>('text');
  const [textContent, setTextContent] = useState('');
  const [urlContent, setUrlContent] = useState('');
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [imageOcrText, setImageOcrText] = useState('');

  // QR mode state
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [qrRawPayload, setQrRawPayload] = useState<string>('');

  // File mode state
  const [docFile, setDocFile] = useState<File | null>(null);
  const [docExtractedText, setDocExtractedText] = useState('');

  const [isLoading, setIsLoading] = useState(false);
  const [errorState, setErrorState] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);

  // Validate inputs
  const validateCurrentInput = (): { valid: boolean; error?: string } => {
    if (activeMode === 'text') {
      if (!textContent.trim()) {
        return { valid: false, error: t.errors.emptyText };
      }
    } else if (activeMode === 'url') {
      if (!urlContent.trim()) {
        return { valid: false, error: t.errors.emptyUrl };
      }
      try {
        const testUrl = urlContent.startsWith('http') ? urlContent : `https://${urlContent}`;
        new URL(testUrl);
      } catch {
        return { valid: false, error: t.errors.invalidUrl };
      }
    } else if (activeMode === 'qr') {
      if (!qrFile && !qrRawPayload.trim()) {
        return { valid: false, error: 'Please select or upload a QR code image to inspect.' };
      }
    } else if (activeMode === 'image') {
      if (!imageFile && !imagePreview) {
        return { valid: false, error: t.errors.noImage };
      }
    } else if (activeMode === 'file') {
      if (!docFile && !docExtractedText.trim()) {
        return { valid: false, error: t.errors.noFile };
      }
    }
    return { valid: true };
  };

  const handleAnalyze = async () => {
    setErrorState(null);
    const validation = validateCurrentInput();
    if (!validation.valid) {
      setErrorState(validation.error || t.errors.generic);
      return;
    }

    setIsLoading(true);
    setAnalysisResult(null);

    // 1. QR Code Analysis (FastAPI + OpenCV)
    if (activeMode === 'qr') {
      try {
        const qrResult = await api.analyzeQr(qrFile, qrRawPayload);
        setAnalysisResult(qrResult);
        setIsLoading(false);
        return;
      } catch (err) {
        console.warn('QR Analysis error, falling back:', err);
      }
    }

    // 2. Asynchronous Large Text Analysis (Non-blocking for heavy message payloads)
    if (activeMode === 'text' && textContent.length > 500) {
      try {
        const job = await api.createAnalysisJob({
          content: textContent,
          type: 'TEXT',
        });
        if (job.job_id) {
          const backendResult = await api.pollJobUntilDone(job.job_id);
          const mappedResult = api.mapToFrontendResult(
            backendResult,
            'text',
            textContent.length > 80 ? `${textContent.slice(0, 80)}...` : textContent
          );
          setAnalysisResult(mappedResult);
          setIsLoading(false);
          return;
        }
      } catch (asyncTextErr) {
        console.warn('Asynchronous text analysis failed, trying synchronous fallback:', asyncTextErr);
      }
    }

    // 3. Python FastAPI / Gateway Message Engine (for standard text analysis)
    if (activeMode === 'text') {
      try {
        const token = localStorage.getItem('pinit_auth_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        let res: Response;
        try {
          res = await fetch(`${API_BASE_URL}/analyze/message`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ content: textContent }),
          });
          if (!res.ok) throw new Error('Gateway returned non-200');
        } catch {
          res = await fetch(`${API_BASE_URL}/analyze/text`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ content: textContent }),
          });
        }
        if (res.ok) {
          const data = await res.json();
          const threatLevelRaw = (data.threat_level || data.risk_level || 'SAFE').toUpperCase();
          const rLevel: RiskLevel =
            threatLevelRaw === 'MALICIOUS' || threatLevelRaw === 'HIGH_RISK' || threatLevelRaw === 'CRITICAL_RISK'
              ? 'high_risk'
              : threatLevelRaw === 'SUSPICIOUS' || threatLevelRaw === 'MEDIUM_RISK' || threatLevelRaw === 'LOW_RISK'
              ? 'suspicious'
              : 'safe';

          setAnalysisResult({
            id: data.id || data.scan_id,
            timestamp: data.timestamp || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            mode: 'text',
            inputSnippet: data.input_snippet || (textContent.length > 80 ? `${textContent.slice(0, 80)}...` : textContent),
            riskScore: data.risk_score,
            riskLevel: rLevel,
            threatCategory: data.threat_category,
            title: data.title,
            summary: data.summary,
            aiExplanation: data.ai_explanation || data.explanation?.why_suspicious,
            structuredExplanation: data.explanation,
            signals: (data.signals || []).map((s: { id: string; category: string; title: string; description: string; severity: 'low' | 'medium' | 'high' }) => ({
              id: s.id,
              category: s.category,
              title: s.title,
              description: s.description,
              severity: s.severity,
            })),
            recommendedActions: data.recommended_actions || data.recommendedActions || [],
            confidenceScore: data.confidence_score,
            evidenceBreakdown: data.evidence_breakdown,
            details: {
              indicatorsFound: (data.signals || []).length,
              safeFactors: data.technical_evidence?.safe_factors || data.safe_factors || [],
              detectedType: data.technical_evidence?.language_detected,
            },
          });
          setIsLoading(false);
          return;
        }
      } catch (fastApiErr) {
        console.warn('FastAPI message engine offline, using local heuristics:', fastApiErr);
      }
    }

    // 4. Asynchronous Pipeline for Files and URLs (POST /analyze → Queue → Worker → Polling)
    if (activeMode === 'url' || activeMode === 'file') {
      try {
        let jobResult: { job_id: string } | null = null;
        if (activeMode === 'url') {
          jobResult = await api.createAnalysisJob({ url: urlContent, type: 'URL' });
        } else if (activeMode === 'file' && docFile) {
          jobResult = await api.createAnalysisJob({ file: docFile, type: 'FILE' });
        }

        if (jobResult?.job_id) {
          const backendResult = await api.pollJobUntilDone(jobResult.job_id);
          const mappedResult = api.mapToFrontendResult(
            backendResult,
            activeMode,
            activeMode === 'url' ? urlContent : docFile?.name || 'File'
          );
          setAnalysisResult(mappedResult);
          setIsLoading(false);
          return;
        }
      } catch (asyncClusterErr) {
        console.warn('Async cluster submission failed, falling back:', asyncClusterErr);
        // Fallback to legacy endpoints if needed
        try {
          let scanId = '';
          if (activeMode === 'url') {
            scanId = await api.submitUrlScan(urlContent);
          } else if (activeMode === 'file' && docFile) {
            scanId = await api.submitFileScan(docFile);
          }

          if (scanId) {
            const backendResult = await api.pollUntilDone(
              activeMode === 'file' ? 'FILE' : 'URL',
              scanId
            );
            const mappedResult = api.mapToFrontendResult(
              backendResult,
              activeMode,
              activeMode === 'url' ? urlContent : docFile?.name || 'File'
            );
            setAnalysisResult(mappedResult);
            setIsLoading(false);
            return;
          }
        } catch (backendErr) {
          console.warn('Backend security cluster unreached, falling back to client-side heuristics:', backendErr);
        }
      }
    }

    // 4. Client-side heuristic fallback (or for Image mode)
    setTimeout(() => {
      try {
        let contentToScan = '';
        if (activeMode === 'text') {
          contentToScan = textContent;
        } else if (activeMode === 'url') {
          contentToScan = urlContent;
        } else if (activeMode === 'qr') {
          contentToScan = qrRawPayload || qrFile?.name || 'QR Code';
        } else if (activeMode === 'image') {
          contentToScan = imageOcrText || (imageFile ? imageFile.name : 'Unknown screenshot');
        } else if (activeMode === 'file') {
          contentToScan = docExtractedText || (docFile ? docFile.name : 'Unknown document');
        }

        const result = analyzeContent(contentToScan, activeMode === 'qr' ? 'url' : activeMode, lang);
        
        // Enrich result with file details if in file mode
        if (activeMode === 'file' && docFile) {
          result.details.fileName = docFile.name;
          result.details.fileSize = `${(docFile.size / 1024).toFixed(1)} KB`;
        }

        setAnalysisResult(result);
        setIsLoading(false);
      } catch {
        setIsLoading(false);
        setErrorState(t.errors.generic);
      }
    }, 1200);
  };

  const handleReset = () => {
    setAnalysisResult(null);
    setErrorState(null);
  };

  const handleModeChange = (mode: AnalysisMode) => {
    setActiveMode(mode);
    setErrorState(null);
    setAnalysisResult(null);
  };

  return (
    <div className="w-full max-w-[672px] mx-auto bg-card rounded-2xl border border-borderDefault shadow-card p-4 sm:p-6 transition-all duration-200">
      {/* Mode switcher is visible when not showing a result */}
      {!analysisResult && !isLoading && (
        <div className="mb-5">
          <ModeSwitcher
            activeMode={activeMode}
            onSelectMode={handleModeChange}
            lang={lang}
            disabled={isLoading}
          />
        </div>
      )}

      {/* Friendly Error Banner */}
      {errorState && !isLoading && !analysisResult && (
        <div
          role="alert"
          className="mb-4 p-3.5 bg-danger-light border border-danger-border rounded-xl flex items-start gap-2.5 text-xs text-danger-dark animate-fadeIn"
        >
          <AlertCircle className="w-4 h-4 text-danger flex-shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold block mb-0.5">Please check your input</span>
            <span>{errorState}</span>
          </div>
        </div>
      )}

      {/* Dynamic Input Areas */}
      {!isLoading && !analysisResult && (
        <div className="space-y-5">
          {activeMode === 'text' && (
            <TextAnalyzer
              value={textContent}
              onChange={(val) => {
                setTextContent(val);
                if (errorState) setErrorState(null);
              }}
              lang={lang}
              disabled={isLoading}
            />
          )}

          {activeMode === 'image' && (
            <ImageUploader
              imageFile={imageFile}
              imagePreview={imagePreview}
              simulatedText={imageOcrText}
              onImageSelected={(file, preview, textHint) => {
                setImageFile(file);
                setImagePreview(preview);
                setImageOcrText(textHint || '');
                if (errorState) setErrorState(null);
              }}
              lang={lang}
              disabled={isLoading}
            />
          )}

          {activeMode === 'url' && (
            <UrlAnalyzer
              value={urlContent}
              onChange={(val) => {
                setUrlContent(val);
                if (errorState) setErrorState(null);
              }}
              lang={lang}
              disabled={isLoading}
            />
          )}

          {activeMode === 'qr' && (
            <QrAnalyzer
              onQrSelected={(file, raw) => {
                setQrFile(file);
                setQrRawPayload(raw || '');
                if (errorState) setErrorState(null);
              }}
              lang={lang}
            />
          )}

          {activeMode === 'file' && (
            <FileAnalyzer
              fileObject={docFile}
              extractedText={docExtractedText}
              onFileSelected={(file, content) => {
                setDocFile(file);
                setDocExtractedText(content);
                if (errorState) setErrorState(null);
              }}
              lang={lang}
              disabled={isLoading}
            />
          )}

          {/* Primary Action Button */}
          <div className="pt-2">
            <AnalyzeButton
              onClick={handleAnalyze}
              isLoading={isLoading}
              lang={lang}
            />
          </div>
        </div>
      )}

      {/* Loading state during scanning */}
      {isLoading && <LoadingState lang={lang} />}

      {/* Results state after scanning */}
      {analysisResult && !isLoading && (
        <ResultCard
          result={analysisResult}
          onReset={handleReset}
          onReportScam={() => onOpenReportScam(analysisResult.inputSnippet)}
          lang={lang}
        />
      )}
    </div>
  );
};
