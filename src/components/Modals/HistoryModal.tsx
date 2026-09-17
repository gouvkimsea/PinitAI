import React, { useEffect, useState } from 'react';
import { X, Clock, ShieldCheck, AlertTriangle, ShieldAlert, Trash2, Globe, FileText, RefreshCw, Loader2, ArrowRight } from 'lucide-react';
import type { Language } from '../../types';
import { api, type ScanHistoryItem } from '../../services/api';

interface HistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
  onSelectScan?: (scan: ScanHistoryItem) => void;
}

export const HistoryModal: React.FC<HistoryModalProps> = ({
  isOpen,
  onClose,
  lang,
  onSelectScan,
}) => {
  const isKm = lang === 'km';
  const [items, setItems] = useState<ScanHistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.getScanHistory(1, 25);
      setItems(res.data);
    } catch (err) {
      setError((err as Error).message || 'Failed to load history.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    if (isOpen) {
      api.getScanHistory(1, 25)
        .then((res) => {
          if (active) {
            setItems(res.data);
            setIsLoading(false);
          }
        })
        .catch((err) => {
          if (active) {
            setError((err as Error).message || 'Failed to load history.');
            setIsLoading(false);
          }
        });
    }
    return () => {
      active = false;
    };
  }, [isOpen]);

  // Handle Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setDeletingId(id);
    try {
      await api.deleteScan(id);
      setItems((prev) => prev.filter((item) => item.id !== id));
    } catch (err) {
      setError((err as Error).message || 'Failed to delete scan.');
    } finally {
      setDeletingId(null);
    }
  };

  const handleRowClick = (scan: ScanHistoryItem) => {
    if (onSelectScan) {
      onSelectScan(scan);
      onClose();
    }
  };

  const getThreatBadge = (level: string) => {
    const norm = (level || '').toUpperCase();
    if (norm === 'MALICIOUS' || norm === 'HIGH_RISK') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-danger-light text-danger border border-danger-border">
          <ShieldAlert className="w-3 h-3" />
          {isKm ? 'ហានិភ័យខ្ពស់' : 'High Risk'}
        </span>
      );
    }
    if (norm === 'SUSPICIOUS') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-warning-light text-warning border border-warning-border">
          <AlertTriangle className="w-3 h-3" />
          {isKm ? 'គួរឱ្យសង្ស័យ' : 'Suspicious'}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-safe-light text-safe border border-safe-border">
        <ShieldCheck className="w-3 h-3" />
        {isKm ? 'សុវត្ថិភាព' : 'Safe'}
      </span>
    );
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="history-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/60 backdrop-blur-xs animate-fadeIn"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl bg-card rounded-2xl border border-borderDefault shadow-elevated p-6 relative flex flex-col max-h-[85vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-borderDefault">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <Clock className="w-5 h-5" />
            </div>
            <div>
              <h2 id="history-modal-title" className="text-base font-bold text-typography-headline">
                {isKm ? 'ប្រវត្តិវិភាគសុវត្ថិភាព' : 'Security Scan History'}
              </h2>
              <p className="text-xs text-typography-muted">
                {isKm ? 'កំណត់ត្រា និងលទ្ធផលវិភាគមុនៗ (ចុចលើកំណត់ត្រាដើម្បីមើល)' : 'Recent threat inspections (click any row to view in scanner)'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={loadData}
              disabled={isLoading}
              className="p-2 text-typography-muted hover:text-typography-headline rounded-lg hover:bg-surfaceInput transition-standard cursor-pointer"
              title={isKm ? 'ផ្ទុកឡើងវិញ' : 'Refresh'}
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-2 text-typography-muted hover:text-typography-headline rounded-lg hover:bg-surfaceInput transition-standard cursor-pointer"
              aria-label="Close modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Error Banner */}
        {error && (
          <div className="mt-3 p-2.5 rounded-lg bg-danger-light border border-danger-border text-xs text-danger">
            {error}
          </div>
        )}

        {/* List Content */}
        <div className="flex-1 overflow-y-auto py-4 space-y-2.5 pr-1">
          {isLoading && items.length === 0 ? (
            <div className="py-12 flex flex-col items-center justify-center text-typography-muted gap-2">
              <Loader2 className="w-6 h-6 animate-spin text-primary" />
              <span className="text-xs">{isKm ? 'កំពុងផ្ទុកប្រវត្តិ...' : 'Loading scan history...'}</span>
            </div>
          ) : items.length === 0 ? (
            <div className="py-12 text-center text-typography-muted space-y-1">
              <Clock className="w-8 h-8 mx-auto opacity-40 mb-2" />
              <p className="text-sm font-medium text-typography-headline">
                {isKm ? 'មិនទាន់មានប្រវត្តិវិភាគនៅឡើយទេ' : 'No scans found'}
              </p>
              <p className="text-xs">
                {isKm ? 'វិភាគ URL ឬឯកសារដើម្បីចាប់ផ្តើម' : 'Scan a suspicious URL or upload a file to see entries here.'}
              </p>
            </div>
          ) : (
            items.map((scan) => (
              <div
                key={scan.id}
                role="button"
                tabIndex={0}
                onClick={() => handleRowClick(scan)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    handleRowClick(scan);
                  }
                }}
                className="p-3.5 rounded-xl border border-borderDefault bg-surfaceInput/40 hover:bg-surfaceInput/90 hover:border-primary/40 transition-standard flex items-center justify-between gap-3 cursor-pointer group focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-8 h-8 rounded-lg bg-card border border-borderDefault flex items-center justify-center text-typography-muted shrink-0 group-hover:text-primary transition-colors">
                    {scan.type === 'URL' ? <Globe className="w-4 h-4" /> : <FileText className="w-4 h-4" />}
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-typography-headline truncate max-w-[280px] sm:max-w-md group-hover:text-primary transition-colors">
                      {scan.target}
                    </p>
                    <div className="flex items-center gap-2 mt-0.5 text-[11px] text-typography-muted">
                      <span>{new Date(scan.created_at).toLocaleDateString()} {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                      <span>•</span>
                      <span>Score: {scan.risk_score}/100</span>
                      {scan.detection_count > 0 && (
                        <>
                          <span>•</span>
                          <span className="text-danger font-medium">{scan.detection_count} threats</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 shrink-0">
                  {getThreatBadge(scan.threat_level)}
                  <button
                    type="button"
                    onClick={(e) => handleDelete(scan.id, e)}
                    disabled={deletingId === scan.id}
                    className="p-1.5 text-typography-muted hover:text-danger rounded-md hover:bg-danger-light/50 transition-standard disabled:opacity-50 cursor-pointer"
                    title={isKm ? 'លុបចេញ' : 'Delete scan'}
                    aria-label="Delete scan record"
                  >
                    {deletingId === scan.id ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Trash2 className="w-3.5 h-3.5" />
                    )}
                  </button>
                  <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-primary group-hover:translate-x-0.5 transition-all hidden sm:block" />
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-borderDefault flex items-center justify-between text-xs text-typography-muted">
          <span>{items.length} {isKm ? 'កំណត់ត្រា' : 'records shown'}</span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 font-medium text-typography-headline bg-surfaceInput hover:bg-borderDefault rounded-lg transition-standard cursor-pointer"
          >
            {isKm ? 'បិទ' : 'Close'}
          </button>
        </div>
      </div>
    </div>
  );
};
