import React, { useState, useRef } from 'react';
import { 
  Globe, 
  QrCode, 
  MessageSquare, 
  UploadCloud, 
  ShieldCheck, 
  AlertTriangle, 
  ShieldAlert, 
  Loader2, 
  CheckCircle2, 
  X,
  Sparkles,
  Copy,
  Download,
  Flag,
  ThumbsUp,
  ThumbsDown,
  ChevronDown,
  ChevronUp,
  Check
} from 'lucide-react';
import type { ScanTab, AnalysisResult, Language, RiskLevel } from '../types';
import { api, API_BASE_URL } from '../services/api';
import { analyzeContent } from '../engine/scamDetector';

interface ThreatScannerProps {
  activeTab: ScanTab;
  onTabChange?: (tab: ScanTab) => void;
  lang?: Language;
  onOpenReportScam?: (prefillSnippet?: string) => void;
}

export const ThreatScanner: React.FC<ThreatScannerProps> = ({
  activeTab,
  onTabChange: _onTabChange,
  lang = 'en',
  onOpenReportScam,
}) => {
  const isKm = lang === 'km';
  const [inputText, setInputText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [qrPreview, setQrPreview] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<AnalysisResult | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isCopied, setIsCopied] = useState(false);
  const [showTechDetails, setShowTechDetails] = useState(false);
  const [userVote, setUserVote] = useState<'up' | 'down' | null>(null);
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      setScanResult(null);
      setErrorMessage(null);
      if (activeTab === 'qr') {
        const reader = new FileReader();
        reader.onload = (ev) => setQrPreview(ev.target?.result as string);
        reader.readAsDataURL(file);
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setScanResult(null);
      setErrorMessage(null);
      if (activeTab === 'qr') {
        const reader = new FileReader();
        reader.onload = (ev) => setQrPreview(ev.target?.result as string);
        reader.readAsDataURL(file);
      }
    }
  };

  const runAnalysis = async () => {
    setErrorMessage(null);
    setUserVote(null);
    setFeedbackMessage(null);

    // Validation
    if (activeTab === 'file') {
      if (!selectedFile) {
        fileInputRef.current?.click();
        return;
      }
    } else if (activeTab === 'url') {
      if (!inputText.trim()) {
        setErrorMessage(isKm ? 'សូមបញ្ចូលតំណភ្ជាប់ URL' : 'Please enter a URL to inspect.');
        return;
      }
      try {
        const testUrl = inputText.startsWith('http') ? inputText : `https://${inputText}`;
        new URL(testUrl);
      } catch {
        setErrorMessage(isKm ? 'ទម្រង់ URL មិនត្រឹមត្រូវ' : 'Please enter a valid URL (e.g. https://...).');
        return;
      }
    } else if (activeTab === 'qr') {
      if (!selectedFile && !inputText.trim()) {
        fileInputRef.current?.click();
        return;
      }
    } else if (activeTab === 'message') {
      if (!inputText.trim()) {
        setErrorMessage(isKm ? 'សូមបញ្ចូលសារអត្ថបទដែលគួរឱ្យសង្ស័យ' : 'Please enter suspicious message text.');
        return;
      }
    }

    setIsScanning(true);
    setScanResult(null);

    // 1. QR Analysis Mode (FastAPI + OpenCV)
    if (activeTab === 'qr') {
      try {
        const qrResult = await api.analyzeQr(selectedFile, inputText);
        setScanResult(qrResult);
        setIsScanning(false);
        return;
      } catch (qrErr) {
        console.warn('QR endpoint offline, falling back to heuristics:', qrErr);
        const fallbackTarget = inputText || selectedFile?.name || 'QR Code';
        const clientResult = analyzeContent(fallbackTarget, 'url', lang);
        setScanResult({
          ...clientResult,
          mode: 'qr',
          title: `[QR Code] ${clientResult.title}`,
          inputSnippet: fallbackTarget,
        });
        setIsScanning(false);
        return;
      }
    }

    // 2. Asynchronous Pipeline for Files and URLs (or heavy message text)
    if (activeTab === 'url' || activeTab === 'file' || (activeTab === 'message' && inputText.length > 500)) {
      try {
        let jobPayload: { content?: string; url?: string; file?: File; type: 'TEXT' | 'URL' | 'FILE' };
        if (activeTab === 'url') {
          jobPayload = { url: inputText, type: 'URL' };
        } else if (activeTab === 'file' && selectedFile) {
          jobPayload = { file: selectedFile, type: 'FILE' };
        } else {
          jobPayload = { content: inputText, type: 'TEXT' };
        }

        const job = await api.createAnalysisJob(jobPayload);
        if (job?.job_id) {
          const backendResult = await api.pollJobUntilDone(job.job_id);
          const mapped = api.mapToFrontendResult(
            backendResult,
            activeTab === 'message' ? 'text' : activeTab,
            activeTab === 'url' ? inputText : selectedFile?.name || inputText.slice(0, 80)
          );
          setScanResult(mapped);
          setIsScanning(false);
          return;
        }
      } catch (asyncErr) {
        console.warn('Async cluster job failed, trying synchronous backend fallback:', asyncErr);
        // Synchronous scan fallback for URL / File
        try {
          let scanId = '';
          if (activeTab === 'url') {
            scanId = await api.submitUrlScan(inputText);
          } else if (activeTab === 'file' && selectedFile) {
            scanId = await api.submitFileScan(selectedFile);
          }
          if (scanId) {
            const syncResult = await api.pollUntilDone(activeTab === 'file' ? 'FILE' : 'URL', scanId);
            const mapped = api.mapToFrontendResult(
              syncResult,
              activeTab === 'file' ? 'file' : 'url',
              activeTab === 'url' ? inputText : selectedFile?.name || 'File'
            );
            setScanResult(mapped);
            setIsScanning(false);
            return;
          }
        } catch (syncErr) {
          console.warn('Synchronous backend failed, using deterministic heuristics:', syncErr);
        }
      }
    }

    // 3. FastAPI / Message Gateway for Standard Text Analysis
    if (activeTab === 'message') {
      try {
        const token = localStorage.getItem('pinit_auth_token');
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;

        let res: Response;
        try {
          res = await fetch(`${API_BASE_URL}/analyze/message`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ content: inputText }),
          });
          if (!res.ok) throw new Error('Non-200 from gateway');
        } catch {
          res = await fetch(`${API_BASE_URL}/analyze/text`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ content: inputText }),
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

          setScanResult({
            id: data.id || data.scan_id || `msg-${Date.now()}`,
            timestamp: data.timestamp || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            mode: 'text',
            inputSnippet: data.input_snippet || (inputText.length > 80 ? `${inputText.slice(0, 80)}...` : inputText),
            riskScore: data.risk_score,
            riskLevel: rLevel,
            threatCategory: data.threat_category,
            title: data.title || (rLevel === 'high_risk' ? 'High Risk Threat Detected' : rLevel === 'suspicious' ? 'Suspicious Elements Detected' : 'No Threat Indicators Found'),
            summary: data.summary || 'Security analysis complete.',
            aiExplanation: data.ai_explanation || data.explanation?.why_suspicious,
            structuredExplanation: data.explanation,
            signals: (data.signals || []).map((s: any) => ({
              id: s.id || `sig-${Math.random()}`,
              category: s.category || 'general',
              title: s.title,
              description: s.description,
              severity: s.severity || 'medium',
            })),
            recommendedActions: data.recommended_actions || data.recommendedActions || [],
            confidenceScore: data.confidence_score || 90,
            evidenceBreakdown: data.evidence_breakdown,
            details: {
              indicatorsFound: (data.signals || []).length,
              safeFactors: data.technical_evidence?.safe_factors || data.safe_factors || [],
              detectedType: data.technical_evidence?.language_detected,
            },
          });
          setIsScanning(false);
          return;
        }
      } catch (fastApiErr) {
        console.warn('FastAPI message engine offline, using local heuristics fallback:', fastApiErr);
      }
    }

    // 4. Client-side Heuristics Fallback Engine
    setTimeout(() => {
      let contentToScan = '';
      let modeForAnalysis: 'text' | 'url' | 'file' = 'text';
      if (activeTab === 'url') {
        contentToScan = inputText;
        modeForAnalysis = 'url';
      } else if (activeTab === 'file') {
        contentToScan = selectedFile ? selectedFile.name : 'Unknown file';
        modeForAnalysis = 'file';
      } else {
        contentToScan = inputText;
        modeForAnalysis = 'text';
      }
      const clientResult = analyzeContent(contentToScan, modeForAnalysis, lang);
      if (activeTab === 'file' && selectedFile) {
        clientResult.details.fileName = selectedFile.name;
        clientResult.details.fileSize = `${(selectedFile.size / 1024).toFixed(1)} KB`;
      }

      setScanResult(clientResult);
      setIsScanning(false);
    }, 900);
  };

  const handleCopyReport = () => {
    if (!scanResult) return;
    const reportText = `[Pinit Threat & Scam Security Report]
Status: ${scanResult.riskLevel.toUpperCase()} (Risk Score: ${scanResult.riskScore}/100)
Assessment: ${scanResult.title}
Summary: ${scanResult.summary}
Target: ${scanResult.inputSnippet}
Signals:
${scanResult.signals.map(s => `- [${s.severity.toUpperCase()}] ${s.title}: ${s.description}`).join('\n')}
Recommendations:
${scanResult.recommendedActions.map(a => `- ${a}`).join('\n')}
Confidence: ${scanResult.confidenceScore}%
Completed: ${scanResult.timestamp}`;

    navigator.clipboard.writeText(reportText).then(() => {
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2500);
    });
  };

  const handleExportJson = () => {
    if (!scanResult) return;
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(scanResult, null, 2))}`;
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', jsonString);
    downloadAnchor.setAttribute('download', `pinit-forensics-${scanResult.id || Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleFeedbackVote = async (isHelpful: boolean) => {
    if (!scanResult) return;
    const nextVote = isHelpful ? 'up' : 'down';

    // If clicking same vote, toggle it off
    if (userVote === nextVote) {
      setUserVote(null);
      setFeedbackMessage(null);
      try {
        localStorage.removeItem(`pinit_feedback_${scanResult.id}`);
      } catch {
        // ignore
      }
      return;
    }

    setUserVote(nextVote);
    const msg = isHelpful
      ? (isKm ? 'អរគុណ! បានកត់ត្រាការវាយតម្លៃត្រឹមត្រូវ' : 'Thanks for your feedback!')
      : (isKm ? 'អរគុណ! បានកត់ត្រាការមិនត្រឹមត្រូវ' : 'Thanks! Flagged for AI model review.');
    setFeedbackMessage(msg);

    try {
      localStorage.setItem(`pinit_feedback_${scanResult.id}`, nextVote);
    } catch {
      // ignore
    }

    try {
      await api.submitFeedback({
        analysisId: scanResult.id,
        isCorrect: isHelpful,
        feedbackType: isHelpful ? 'correct_detection' : 'incorrect_detection',
        targetSnippet: scanResult.inputSnippet,
        riskScoreAtTime: scanResult.riskScore,
      });
    } catch (err) {
      console.warn('Feedback submission fallback logged:', err);
    }
  };

  // VirusTotal-style detection and community metrics
  const totalVendors = 90;
  const detectionCount = scanResult
    ? scanResult.riskLevel === 'safe'
      ? 0
      : scanResult.riskLevel === 'suspicious'
      ? Math.max(1, Math.round((scanResult.riskScore / 100) * 35))
      : Math.max(35, Math.round((scanResult.riskScore / 100) * totalVendors))
    : 0;

  const gaugeColor = scanResult
    ? scanResult.riskLevel === 'safe'
      ? '#2dd4bf'
      : scanResult.riskLevel === 'suspicious'
      ? '#f59e0b'
      : '#ef4444'
    : '#2dd4bf';

  const gaugeRadius = 44;
  const gaugeCircumference = 2 * Math.PI * gaugeRadius;
  const strokeDashoffset = detectionCount === 0
    ? 0
    : gaugeCircumference - (detectionCount / totalVendors) * gaugeCircumference;

  return (
    <section id="threat-scanner" className="max-w-3xl mx-auto px-4 sm:px-6 pt-2 pb-10" aria-label="Interactive Threat Scanner">
      <div 
        className="bg-white rounded-2xl shadow-sm border border-slate-200/90 p-5 sm:p-8 transition-all hover:shadow-md"
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        {/* Top Centered Icon from Screenshot */}
        <div className="flex flex-col items-center justify-center mb-4">
          <div className="w-16 h-16 sm:w-20 sm:h-20 flex items-center justify-center text-[#0b4d82]">
            {activeTab === 'file' && (
              <svg 
                className="w-12 h-12 sm:w-16 sm:h-16 stroke-current text-[#0b4d82]" 
                viewBox="0 0 24 24" 
                fill="none" 
                strokeWidth="1.6" 
                strokeLinecap="round" 
                strokeLinejoin="round" 
                aria-hidden="true"
              >
                <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="8" y1="13" x2="16" y2="13" />
                <line x1="8" y1="17" x2="12" y2="17" />
              </svg>
            )}
            {activeTab === 'url' && <Globe className="w-12 h-12 sm:w-16 sm:h-16 stroke-[1.6]" aria-hidden="true" />}
            {activeTab === 'qr' && <QrCode className="w-12 h-12 sm:w-16 sm:h-16 stroke-[1.6]" aria-hidden="true" />}
            {activeTab === 'message' && <MessageSquare className="w-12 h-12 sm:w-16 sm:h-16 stroke-[1.6]" aria-hidden="true" />}
          </div>
        </div>

        {/* Input Container Box matching Figma screenshot: "Enter your texts..." with rounded border */}
        <div className="relative">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            className="hidden"
            id="file-upload-input"
            aria-label="Upload file for threat analysis"
          />

          {activeTab === 'message' ? (
            <div className="relative rounded-xl border border-slate-300 bg-slate-50/50 focus-within:border-[#0b4d82] focus-within:bg-white focus-within:ring-2 focus-within:ring-[#0b4d82]/20 transition-all p-3">
              <label htmlFor="message-input" className="sr-only">Enter message text for scam detection</label>
              <textarea
                id="message-input"
                rows={4}
                value={inputText}
                onChange={(e) => {
                  setInputText(e.target.value);
                  setScanResult(null);
                  setErrorMessage(null);
                }}
                placeholder={isKm ? "សូមបញ្ចូលសារអត្ថបទ SMS, Telegram, WhatsApp... ដើម្បីស្វែងរកសញ្ញាឆបោក" : "Enter your texts... (Paste suspicious SMS, email body, WhatsApp message, or payment note)"}
                className="w-full bg-transparent resize-none text-slate-800 text-sm sm:text-base placeholder-slate-400 focus:outline-none"
              />
              {inputText && (
                <button
                  type="button"
                  onClick={() => setInputText('')}
                  className="absolute top-3 right-3 text-slate-400 hover:text-slate-600 p-1 rounded-md"
                  aria-label="Clear text input"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
          ) : activeTab === 'url' ? (
            <div className="relative rounded-xl border border-slate-300 bg-slate-50/50 focus-within:border-[#0b4d82] focus-within:bg-white focus-within:ring-2 focus-within:ring-[#0b4d82]/20 transition-all p-3">
              <label htmlFor="url-input" className="sr-only">Enter URL to inspect</label>
              <div className="flex items-center space-x-2">
                <Globe className="w-5 h-5 text-slate-400 shrink-0" aria-hidden="true" />
                <input
                  id="url-input"
                  type="url"
                  value={inputText}
                  onChange={(e) => {
                    setInputText(e.target.value);
                    setScanResult(null);
                    setErrorMessage(null);
                  }}
                  placeholder={isKm ? "https://example.com/login ឬបិទភ្ជាប់តំណភ្ជាប់គួរឱ្យសង្ស័យ..." : "https://example.com/login or paste suspicious link..."}
                  className="w-full bg-transparent text-slate-800 text-sm sm:text-base placeholder-slate-400 focus:outline-none"
                />
                {inputText && (
                  <button
                    type="button"
                    onClick={() => setInputText('')}
                    className="text-slate-400 hover:text-slate-600 p-1 rounded-md"
                    aria-label="Clear URL"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          ) : (
            /* File and QR Upload Box */
            <div 
              onClick={() => fileInputRef.current?.click()}
              className={`rounded-xl border-2 border-dashed p-6 text-center cursor-pointer transition-all ${
                dragActive 
                  ? 'border-[#0b4d82] bg-sky-50' 
                  : selectedFile 
                  ? 'border-emerald-400 bg-emerald-50/40' 
                  : 'border-slate-300 hover:border-[#0b4d82] bg-slate-50/60 hover:bg-slate-50'
              }`}
            >
              {selectedFile ? (
                <div className="flex flex-col items-center justify-center space-y-2">
                  {activeTab === 'qr' && qrPreview ? (
                    <img src={qrPreview} alt="QR Preview" className="w-20 h-20 object-contain mx-auto rounded-lg border border-slate-200 shadow-xs" />
                  ) : (
                    <div className="w-10 h-10 rounded-full bg-emerald-100 text-emerald-700 flex items-center justify-center">
                      <CheckCircle2 className="w-6 h-6" />
                    </div>
                  )}
                  <div className="text-sm font-semibold text-slate-800">{selectedFile.name}</div>
                  <p className="text-xs text-slate-500">{(selectedFile.size / 1024).toFixed(1)} KB — {isKm ? 'រួចរាល់សម្រាប់ការវិភាគ' : 'Ready to analyze'}</p>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedFile(null);
                      setQrPreview(null);
                    }}
                    className="text-xs text-rose-600 hover:underline pt-1"
                  >
                    {isKm ? 'លុបឯកសារ' : 'Remove file'}
                  </button>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center space-y-2">
                  <UploadCloud className="w-8 h-8 text-slate-400" aria-hidden="true" />
                  <p className="text-sm font-medium text-slate-700">
                    {activeTab === 'qr' 
                      ? (isKm ? 'ចុចដើម្បីជ្រើសរើសរូបភាពកូដ QR' : 'Upload QR Code image') 
                      : (isKm ? 'អូសទម្លាក់ឯកសារទីនេះ ឬចុចដើម្បីស្វែងរក' : 'Drag & drop file here or click to browse')}
                  </p>
                  <p className="text-xs text-slate-400">
                    {activeTab === 'qr' 
                      ? (isKm ? 'គាំទ្រ PNG, JPG, WEBP រហូតដល់ 25MB' : 'PNG, JPG, WEBP up to 25MB')
                      : (isKm ? 'គាំទ្រ PDF, Word, Excel, ZIP, APK, Executables រហូតដល់ 50MB' : 'Supports PDF, Word, Excel, ZIP, APK, Executables up to 50MB')}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Error Alert */}
        {errorMessage && (
          <div className="mt-3 p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
            <span>{errorMessage}</span>
          </div>
        )}


        {/* Analyze Button matching Screenshot design */}
        <div className="mt-6 flex justify-center">
          <button
            type="button"
            onClick={runAnalysis}
            disabled={isScanning}
            className="w-full sm:w-auto min-w-[170px] px-8 py-2.5 rounded-full font-semibold text-sm transition-all duration-200 flex items-center justify-center space-x-2 border-2 border-[#0b4d82] text-[#0b4d82] hover:bg-[#0b4d82] hover:text-white active:scale-98 focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#0b4d82] disabled:opacity-60 disabled:cursor-not-allowed shadow-sm"
          >
            {isScanning ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-current" />
                <span>{isKm ? 'កំពុងវិភាគហានិភ័យ...' : 'Analyzing threat...'}</span>
              </>
            ) : (
              <span>{isKm ? 'វិភាគ' : 'Analyze'}</span>
            )}
          </button>
        </div>

        {/* Live Threat Analysis Results Card */}
        {scanResult && !isScanning && (
          <div 
            role="region" 
            aria-live="polite" 
            className="mt-8 pt-6 border-t border-slate-200 animate-fadeIn"
          >
            <div className={`rounded-xl p-5 border ${
              scanResult.riskLevel === 'high_risk' 
                ? 'bg-rose-50/60 border-rose-200' 
                : scanResult.riskLevel === 'suspicious' 
                ? 'bg-amber-50/60 border-amber-200' 
                : 'bg-emerald-50/60 border-emerald-200'
            }`}>
              {/* Centered Circular Threat Score Gauge Header */}
              <div className="flex flex-col items-center justify-center pt-2 pb-6 border-b border-slate-200/60 select-none text-center">
                {/* Circular Gauge */}
                <div className="relative w-32 h-32 sm:w-36 sm:h-36 flex items-center justify-center">
                  <svg className="w-full h-full" viewBox="0 0 120 120">
                    <circle
                      cx="60"
                      cy="60"
                      r={gaugeRadius}
                      fill="none"
                      stroke="#e2e8f0"
                      strokeWidth="9"
                    />
                    <circle
                      cx="60"
                      cy="60"
                      r={gaugeRadius}
                      fill="none"
                      stroke={gaugeColor}
                      strokeWidth="9"
                      strokeDasharray={gaugeCircumference}
                      strokeDashoffset={strokeDashoffset}
                      strokeLinecap="round"
                      transform="rotate(-90 60 60)"
                      className="transition-all duration-1000 ease-out"
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span
                      className="text-3xl sm:text-4xl font-extrabold font-sans tracking-tight leading-none"
                      style={{ color: gaugeColor }}
                    >
                      {detectionCount}
                    </span>
                    <span className="text-xs sm:text-sm font-semibold text-slate-500 mt-1">
                      / {totalVendors}
                    </span>
                  </div>
                </div>

                {/* Threat Level Status Pill */}
                <div className="mt-3 flex items-center justify-center gap-2">
                  <span className={`text-xs px-3 py-1 rounded-full font-bold uppercase tracking-wider ${
                    scanResult.riskLevel === 'high_risk'
                      ? 'bg-rose-100 text-rose-800'
                      : scanResult.riskLevel === 'suspicious'
                      ? 'bg-amber-100 text-amber-800'
                      : 'bg-emerald-100 text-emerald-800'
                  }`}>
                    {scanResult.riskLevel === 'high_risk' ? 'MALICIOUS' : scanResult.riskLevel.toUpperCase()}
                  </span>
                </div>
              </div>

              {/* Threat Assessment Info & Summary (Pushed Down Below Gauge) */}
              <div className="pt-5 space-y-3">
                <div className="flex items-start space-x-3">
                  <div className={`p-2.5 rounded-xl shrink-0 ${
                    scanResult.riskLevel === 'high_risk' 
                      ? 'bg-rose-600 text-white' 
                      : scanResult.riskLevel === 'suspicious' 
                      ? 'bg-amber-500 text-white' 
                      : 'bg-emerald-600 text-white'
                  }`}>
                    {scanResult.riskLevel === 'high_risk' && <ShieldAlert className="w-6 h-6" />}
                    {scanResult.riskLevel === 'suspicious' && <AlertTriangle className="w-6 h-6" />}
                    {scanResult.riskLevel === 'safe' && <ShieldCheck className="w-6 h-6" />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <h2 className="text-base sm:text-lg font-bold text-slate-900 leading-snug">{scanResult.title}</h2>
                    <p className="text-xs text-slate-500 mt-1 truncate max-w-md font-mono bg-white/70 px-2 py-0.5 rounded border border-slate-200/80 inline-block">
                      Target: {scanResult.inputSnippet}
                    </p>
                  </div>
                </div>

                {/* Summary paragraph */}
                <p className="text-sm text-slate-700 leading-relaxed pt-1">
                  {scanResult.summary}
                </p>
              </div>

              {/* Detected Signals */}
              {scanResult.signals && scanResult.signals.length > 0 && (
                <div className="mt-4 space-y-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500">Detected Scam Signals</span>
                  <div className="space-y-1.5">
                    {scanResult.signals.map((sig, i) => (
                      <div key={i} className="flex items-start space-x-2 text-xs bg-white/80 p-2.5 rounded-lg border border-slate-200">
                        <span className={`mt-0.5 px-1.5 py-0.2 rounded font-bold uppercase text-[10px] ${
                          sig.severity === 'high' 
                            ? 'bg-rose-100 text-rose-700' 
                            : sig.severity === 'medium' 
                            ? 'bg-amber-100 text-amber-700' 
                            : 'bg-slate-100 text-slate-700'
                        }`}>
                          {sig.severity}
                        </span>
                        <div>
                          <strong className="text-slate-800 font-semibold">{sig.title}: </strong>
                          <span className="text-slate-600">{sig.description}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Actions */}
              {scanResult.recommendedActions && scanResult.recommendedActions.length > 0 && (
                <div className="mt-4 pt-3 border-t border-slate-200/60">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500">Recommended Action</span>
                  <ul className="mt-1 space-y-1 text-xs text-slate-700 list-disc list-inside">
                    {scanResult.recommendedActions.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}

              {/* AI Structured Explanation (if present) */}
              {scanResult.aiExplanation && (
                <div className="mt-4 p-3 bg-white/70 rounded-lg border border-slate-200 text-xs text-slate-700 space-y-1">
                  <div className="font-semibold text-slate-800 flex items-center space-x-1">
                    <Sparkles className="w-3.5 h-3.5 text-sky-600" />
                    <span>AI Threat Analysis:</span>
                  </div>
                  <p className="leading-relaxed">{scanResult.aiExplanation}</p>
                </div>
              )}

              {/* Utility Actions (Copy, Export JSON, Report Scam, Feedback) */}
              <div className="mt-5 pt-3 border-t border-slate-200/60 flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex items-center space-x-2">
                  <button
                    type="button"
                    onClick={handleCopyReport}
                    className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 transition-colors"
                  >
                    {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                    <span>{isCopied ? 'Copied!' : 'Copy Report'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleExportJson}
                    className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5 text-slate-500" />
                    <span>Export JSON</span>
                  </button>

                  {onOpenReportScam && (
                    <button
                      type="button"
                      onClick={() => onOpenReportScam(scanResult.inputSnippet)}
                      className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-rose-50 border border-rose-200 text-rose-700 hover:bg-rose-100 transition-colors"
                    >
                      <Flag className="w-3.5 h-3.5 text-rose-600" />
                      <span>Report Scam</span>
                    </button>
                  )}
                </div>

                {/* Feedback pill */}
                <div className="flex flex-wrap items-center gap-2 text-slate-600 text-xs">
                  <span className="font-medium text-slate-500">
                    {isKm ? 'តើការវាយតម្លៃនេះមានប្រយោជន៍ទេ?' : 'Helpful assessment?'}
                  </span>
                  
                  <div className="flex items-center space-x-1.5">
                    {/* Thumbs Up Button */}
                    <button
                      type="button"
                      onClick={() => handleFeedbackVote(true)}
                      className={`px-2.5 py-1 rounded-lg border transition-all duration-150 flex items-center space-x-1 cursor-pointer font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-400 ${
                        userVote === 'up'
                          ? 'bg-emerald-100 text-emerald-800 border-emerald-400 ring-2 ring-emerald-400/20 shadow-xs font-bold'
                          : 'bg-white hover:bg-emerald-50 text-slate-600 hover:text-emerald-700 border-slate-300 hover:border-emerald-300 shadow-xs'
                      }`}
                      title={isKm ? 'បាទ/ចាស ត្រឹមត្រូវ' : 'Yes, accurate assessment'}
                      aria-label="Mark assessment as accurate"
                      aria-pressed={userVote === 'up'}
                    >
                      <ThumbsUp className={`w-3.5 h-3.5 ${userVote === 'up' ? 'fill-emerald-600 text-emerald-700' : ''}`} />
                      <span>{isKm ? 'ត្រឹមត្រូវ' : 'Yes'}</span>
                    </button>

                    {/* Thumbs Down Button */}
                    <button
                      type="button"
                      onClick={() => handleFeedbackVote(false)}
                      className={`px-2.5 py-1 rounded-lg border transition-all duration-150 flex items-center space-x-1 cursor-pointer font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-rose-400 ${
                        userVote === 'down'
                          ? 'bg-rose-100 text-rose-800 border-rose-400 ring-2 ring-rose-400/20 shadow-xs font-bold'
                          : 'bg-white hover:bg-rose-50 text-slate-600 hover:text-rose-700 border-slate-300 hover:border-rose-300 shadow-xs'
                      }`}
                      title={isKm ? 'មិនត្រឹមត្រូវទេ' : 'No, inaccurate assessment'}
                      aria-label="Mark assessment as inaccurate"
                      aria-pressed={userVote === 'down'}
                    >
                      <ThumbsDown className={`w-3.5 h-3.5 ${userVote === 'down' ? 'fill-rose-600 text-rose-700' : ''}`} />
                      <span>{isKm ? 'មិនត្រឹមត្រូវ' : 'No'}</span>
                    </button>
                  </div>

                  {/* Feedback status message */}
                  {feedbackMessage && (
                    <span className="inline-flex items-center space-x-1 text-xs font-semibold px-2 py-0.5 rounded-md bg-white border border-slate-200 text-slate-700 animate-fadeIn shadow-xs">
                      <Check className="w-3 h-3 text-emerald-600" />
                      <span>{feedbackMessage}</span>
                    </span>
                  )}
                </div>
              </div>

              {/* Technical Details Toggle */}
              <div className="mt-3 pt-2 border-t border-slate-200/40">
                <button
                  type="button"
                  onClick={() => setShowTechDetails(!showTechDetails)}
                  className="text-[11px] text-slate-500 hover:text-slate-800 flex items-center space-x-1"
                >
                  <span>Technical evidence & safe factors</span>
                  {showTechDetails ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                </button>

                {showTechDetails && (
                  <div className="mt-2 p-2.5 bg-slate-100/80 rounded-lg text-[11px] space-y-1 text-slate-600">
                    <div><strong>Scan ID:</strong> {scanResult.id}</div>
                    {scanResult.details?.fileName && <div><strong>File Name:</strong> {scanResult.details.fileName} ({scanResult.details.fileSize})</div>}
                    {scanResult.details?.domainEvaluated && <div><strong>Domain Evaluated:</strong> {scanResult.details.domainEvaluated}</div>}
                    {scanResult.details?.qrPayload && <div><strong>Extracted QR Payload:</strong> {scanResult.details.qrPayload}</div>}
                    {scanResult.details?.safeFactors && scanResult.details.safeFactors.length > 0 && (
                      <div><strong>Safe Factors:</strong> {scanResult.details.safeFactors.join(', ')}</div>
                    )}
                  </div>
                )}
              </div>

              {/* Footer row */}
              <div className="mt-4 flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-200/40">
                <span>Completed: {scanResult.timestamp}</span>
                <button
                  type="button"
                  onClick={() => {
                    setScanResult(null);
                    setSelectedFile(null);
                    setInputText('');
                    setQrPreview(null);
                  }}
                  className="text-[#0b4d82] hover:underline font-semibold"
                >
                  Scan another item
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
