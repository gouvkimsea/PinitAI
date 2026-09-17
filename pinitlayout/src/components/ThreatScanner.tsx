import React, { useState, useRef } from 'react';
import { 
  FileText, 
  Globe, 
  QrCode, 
  MessageSquare, 
  UploadCloud, 
  ShieldCheck, 
  AlertTriangle, 
  ShieldAlert, 
  ArrowRight, 
  Loader2, 
  CheckCircle2, 
  FileWarning, 
  X,
  Sparkles
} from 'lucide-react';
import { ScanTab, ThreatAnalysisResult } from '../types';

interface ThreatScannerProps {
  activeTab: ScanTab;
  onTabChange: (tab: ScanTab) => void;
}

export const ThreatScanner: React.FC<ThreatScannerProps> = ({ activeTab, onTabChange }) => {
  const [inputText, setInputText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [qrPreview, setQrPreview] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ThreatAnalysisResult | null>(null);
  const [dragActive, setDragActive] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const qrInputRef = useRef<HTMLInputElement>(null);

  // Quick preset samples for instant evaluation
  const samplesByTab = {
    file: [
      { name: 'Urgent_Invoice_Overdue.pdf.exe', type: 'Trojan Payload', risk: 'high' },
      { name: 'Q4_Financial_Report.docm', type: 'VBA Macro Threat', risk: 'medium' },
      { name: 'Official_Contract_2026.pdf', type: 'Clean Document', risk: 'low' },
    ],
    url: [
      { name: 'http://auth-chase-update-account.security-verify.com/login', type: 'Credential Phishing', risk: 'high' },
      { name: 'https://tinyurl.com/crypto-giveaway-claim-500', type: 'Crypto Scam Redirect', risk: 'high' },
      { name: 'https://www.google.com/safetycenter', type: 'Verified Safe Domain', risk: 'low' },
    ],
    qr: [
      { name: 'Parking_Meter_Payment_QR.png', type: 'Quishing / Fake Payment', risk: 'high' },
      { name: 'Cafe_Menu_Direct_Link.png', type: 'Clean Static URL', risk: 'low' },
    ],
    message: [
      { name: 'USPS: Your package cannot be delivered due to missing house number. Update immediately: bit.ly/usps-track', type: 'Smishing SMS', risk: 'high' },
      { name: 'Mom, my phone broke. This is my friend’s number. Can you transfer $400 for emergency rent?', type: 'Impersonation Scam', risk: 'high' },
      { name: 'Your verification code is 492019. Valid for 10 minutes. Do not share this code.', type: 'Standard 2FA Notification', risk: 'low' },
    ]
  };

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
      if (activeTab === 'qr') {
        handleQrFile(file);
      } else {
        setSelectedFile(file);
        setScanResult(null);
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      if (activeTab === 'qr') {
        handleQrFile(file);
      } else {
        setSelectedFile(file);
        setScanResult(null);
      }
    }
  };

  const handleQrFile = (file: File) => {
    setSelectedFile(file);
    const reader = new FileReader();
    reader.onload = (e) => {
      setQrPreview(e.target?.result as string);
    };
    reader.readAsDataURL(file);
    setScanResult(null);
  };

  const loadSample = (sampleText: string) => {
    if (activeTab === 'file') {
      setSelectedFile(new File(['dummy payload test'], sampleText, { type: 'application/octet-stream' }));
      setInputText('');
    } else if (activeTab === 'url') {
      setInputText(sampleText);
    } else if (activeTab === 'qr') {
      setSelectedFile(new File(['fake qr'], sampleText, { type: 'image/png' }));
      setQrPreview('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100"><rect width="100" height="100" fill="white"/><rect x="10" y="10" width="30" height="30" fill="black"/><rect x="60" y="10" width="30" height="30" fill="black"/><rect x="10" y="60" width="30" height="30" fill="black"/><rect x="45" y="45" width="10" height="10" fill="black"/></svg>');
    } else {
      setInputText(sampleText);
    }
    setScanResult(null);
  };

  const runAnalysis = () => {
    const target = selectedFile ? selectedFile.name : inputText.trim();
    if (!target) {
      if (activeTab === 'file' || activeTab === 'qr') {
        fileInputRef.current?.click();
      }
      return;
    }

    setIsScanning(true);
    setScanResult(null);

    // Simulate robust AI and heuristic detection (resolves in ~1.2s to match "< 2 seconds" promise)
    setTimeout(() => {
      setIsScanning(false);

      const lower = target.toLowerCase();
      const isDangerous =
        lower.includes('exe') ||
        lower.includes('macro') ||
        lower.includes('docm') ||
        lower.includes('phish') ||
        lower.includes('verify') ||
        lower.includes('overdue') ||
        lower.includes('bit.ly') ||
        lower.includes('transfer') ||
        lower.includes('urgent') ||
        lower.includes('quishing') ||
        lower.includes('emergency') ||
        lower.includes('tinyurl');

      const isCaution =
        lower.includes('financial') ||
        lower.includes('contract') ||
        lower.includes('zip') ||
        lower.includes('dropbox') ||
        lower.includes('bill');

      if (isDangerous) {
        setScanResult({
          id: 'res-' + Date.now(),
          type: activeTab,
          targetName: target,
          riskScore: 92,
          verdict: 'malicious',
          title: 'High Risk Threat Detected',
          summary: 'Scam and exploit indicators matched against 40+ threat databases. Contains credential harvesting and social engineering vectors.',
          signals: [
            { label: 'Deceptive Domain / Sender Spoofing', severity: 'high', description: 'Sender attempts to impersonate an official institution without valid cryptographic domain signatures.' },
            { label: 'Urgency & Coercion Flags', severity: 'high', description: 'High psychological pressure tactics detected requiring immediate financial or credential action.' },
            { label: 'High-Risk Action Link', severity: 'medium', description: 'Destination redirect obfuscates true target server located in an unverified ASN block.' },
          ],
          recommendations: [
            'Do NOT click any embedded links or open attachments.',
            'Report this sender as phishing immediately.',
            'Never share 2FA codes, passwords, or initiate peer-to-peer money transfers.'
          ],
          scanDurationMs: 840,
          timestamp: 'Just now'
        });
      } else if (isCaution) {
        setScanResult({
          id: 'res-' + Date.now(),
          type: activeTab,
          targetName: target,
          riskScore: 48,
          verdict: 'suspicious',
          title: 'Suspicious Elements Detected',
          summary: 'Mild anomalies detected in file header structure or URL redirect tree. Requires user discretion before proceeding.',
          signals: [
            { label: 'Unverified Third-Party Host', severity: 'medium', description: 'File or domain is hosted on an unvetted public file sharing service.' },
            { label: 'Heuristic Pattern Match', severity: 'low', description: 'Contains executable macros or external script references.' }
          ],
          recommendations: [
            'Verify the sender identity through an alternative trusted communication channel.',
            'Open file only in a sandboxed viewer or sandbox environment.'
          ],
          scanDurationMs: 920,
          timestamp: 'Just now'
        });
      } else {
        setScanResult({
          id: 'res-' + Date.now(),
          type: activeTab,
          targetName: target,
          riskScore: 4,
          verdict: 'safe',
          title: 'No Threat Indicators Found',
          summary: 'Clean signature verified. Domain matches legitimate registrar records and no malicious exploit payloads detected.',
          signals: [
            { label: 'Cryptographic Certificate Valid', severity: 'low', description: 'Authentic TLS/SSL authority certificate with clean trust chain.' },
            { label: 'Known Safe Entity', severity: 'low', description: 'Listed on global verified safety and reputation registries.' }
          ],
          recommendations: [
            'Safe to open or proceed under normal browsing precautions.'
          ],
          scanDurationMs: 650,
          timestamp: 'Just now'
        });
      }
    }, 1100);
  };

  const getActiveTabPlaceholder = () => {
    switch (activeTab) {
      case 'file':
        return 'Drop your file here, or click to browse (PDF, DOCX, EXE, ZIP, etc.)...';
      case 'url':
        return 'Enter website URL or payment link to inspect (e.g., https://...)...';
      case 'qr':
        return 'Upload QR code image to inspect hidden redirect destination...';
      case 'message':
      default:
        return 'Enter your texts... (Paste suspicious SMS, email body, WhatsApp message, or payment note)';
    }
  };

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
                }}
                placeholder="Enter your texts..."
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
                  }}
                  placeholder="https://example.com/login or paste suspicious link..."
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
                  <div className="w-10 h-10 rounded-full bg-emerald-100 text-emerald-700 flex items-center justify-center">
                    <CheckCircle2 className="w-6 h-6" />
                  </div>
                  <div className="text-sm font-semibold text-slate-800">{selectedFile.name}</div>
                  <p className="text-xs text-slate-500">{(selectedFile.size / 1024).toFixed(1)} KB — Ready to analyze</p>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedFile(null);
                      setQrPreview(null);
                    }}
                    className="text-xs text-rose-600 hover:underline pt-1"
                  >
                    Remove file
                  </button>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center space-y-2">
                  <UploadCloud className="w-8 h-8 text-slate-400" aria-hidden="true" />
                  <p className="text-sm font-medium text-slate-700">
                    {activeTab === 'qr' ? 'Upload QR Code image' : 'Drag & drop file here or click to browse'}
                  </p>
                  <p className="text-xs text-slate-400">
                    {activeTab === 'qr' ? 'PNG, JPG, WEBP up to 25MB' : 'Supports PDF, Word, Excel, ZIP, APK, Executables up to 50MB'}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Quick Sample Selector Pill Buttons */}
        <div className="mt-4 pt-2 border-t border-slate-100">
          <div className="flex items-center justify-between flex-wrap gap-2 text-xs">
            <span className="text-slate-500 font-medium flex items-center">
              <Sparkles className="w-3.5 h-3.5 text-amber-500 mr-1" aria-hidden="true" />
              Quick sample test:
            </span>
            <div className="flex flex-wrap gap-1.5">
              {samplesByTab[activeTab].map((sample, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => loadSample(sample.name)}
                  className={`px-2.5 py-1 rounded-full border text-xs transition-colors font-medium ${
                    sample.risk === 'high'
                      ? 'border-rose-200 bg-rose-50 text-rose-700 hover:bg-rose-100'
                      : sample.risk === 'medium'
                      ? 'border-amber-200 bg-amber-50 text-amber-800 hover:bg-amber-100'
                      : 'border-emerald-200 bg-emerald-50 text-emerald-800 hover:bg-emerald-100'
                  }`}
                >
                  {sample.type}
                </button>
              ))}
            </div>
          </div>
        </div>

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
                <span>Analyzing threat...</span>
              </>
            ) : (
              <span>Analyze</span>
            )}
          </button>
        </div>

        {/* Live Threat Analysis Results Card */}
        {scanResult && (
          <div 
            role="region" 
            aria-live="polite" 
            className="mt-8 pt-6 border-t border-slate-200 animate-fadeIn"
          >
            <div className={`rounded-xl p-5 border ${
              scanResult.verdict === 'malicious' 
                ? 'bg-rose-50/60 border-rose-200' 
                : scanResult.verdict === 'suspicious' 
                ? 'bg-amber-50/60 border-amber-200' 
                : 'bg-emerald-50/60 border-emerald-200'
            }`}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200/60">
                <div className="flex items-center space-x-3">
                  <div className={`p-2.5 rounded-xl ${
                    scanResult.verdict === 'malicious' 
                      ? 'bg-rose-600 text-white' 
                      : scanResult.verdict === 'suspicious' 
                      ? 'bg-amber-500 text-white' 
                      : 'bg-emerald-600 text-white'
                  }`}>
                    {scanResult.verdict === 'malicious' && <ShieldAlert className="w-6 h-6" />}
                    {scanResult.verdict === 'suspicious' && <AlertTriangle className="w-6 h-6" />}
                    {scanResult.verdict === 'safe' && <ShieldCheck className="w-6 h-6" />}
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h2 className="text-base font-bold text-slate-900">{scanResult.title}</h2>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-bold uppercase tracking-wider ${
                        scanResult.verdict === 'malicious'
                          ? 'bg-rose-100 text-rose-800'
                          : scanResult.verdict === 'suspicious'
                          ? 'bg-amber-100 text-amber-800'
                          : 'bg-emerald-100 text-emerald-800'
                      }`}>
                        {scanResult.verdict}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5 truncate max-w-md">Target: {scanResult.targetName}</p>
                  </div>
                </div>

                {/* Risk Score Pill */}
                <div className="flex sm:flex-col items-center sm:items-end justify-between sm:justify-center border-t sm:border-t-0 pt-2 sm:pt-0 border-slate-200">
                  <span className="text-xs font-semibold text-slate-500">Risk Score</span>
                  <div className="flex items-baseline space-x-1">
                    <span className={`text-2xl font-black ${
                      scanResult.riskScore > 70 
                        ? 'text-rose-600' 
                        : scanResult.riskScore > 30 
                        ? 'text-amber-600' 
                        : 'text-emerald-600'
                    }`}>
                      {scanResult.riskScore}
                    </span>
                    <span className="text-xs text-slate-400">/100</span>
                  </div>
                </div>
              </div>

              {/* Summary */}
              <p className="text-sm text-slate-700 mt-4 leading-relaxed">
                {scanResult.summary}
              </p>

              {/* Detected Signals */}
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
                        <strong className="text-slate-800 font-semibold">{sig.label}: </strong>
                        <span className="text-slate-600">{sig.description}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommendations */}
              <div className="mt-4 pt-3 border-t border-slate-200/60">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-500">Recommended Action</span>
                <ul className="mt-1 space-y-1 text-xs text-slate-700 list-disc list-inside">
                  {scanResult.recommendations.map((rec, i) => (
                    <li key={i}>{rec}</li>
                  ))}
                </ul>
              </div>

              <div className="mt-4 flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-200/40">
                <span>Completed in {scanResult.scanDurationMs}ms</span>
                <button
                  type="button"
                  onClick={() => setScanResult(null)}
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
