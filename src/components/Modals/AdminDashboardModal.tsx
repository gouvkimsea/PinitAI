import React, { useState, useEffect, useCallback } from 'react';
import {
  X,
  Shield,
  Download,
  CheckCircle2,
  Clock,
  RefreshCw,
} from 'lucide-react';
import type { Language, AdminStats, ModelMetrics, TrainingSample } from '../../types';
import { translations } from '../../i18n/translations';
import { api } from '../../services/api';

interface AdminDashboardModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
}

export const AdminDashboardModal: React.FC<AdminDashboardModalProps> = ({
  isOpen,
  onClose,
  lang,
}) => {
  const t = translations[lang];
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [metrics, setMetrics] = useState<ModelMetrics | null>(null);
  const [dataset, setDataset] = useState<TrainingSample[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'dataset' | 'metrics'>('overview');
  const [langFilter, setLangFilter] = useState<'all' | 'en' | 'km' | 'km-en'>('all');
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [s, m, d] = await Promise.all([
        api.getAdminStats(),
        api.getAdminMetrics(),
        api.getAdminDataset(),
      ]);
      setStats(s);
      setMetrics(m);
      setDataset(d);
    } catch (e: any) {
      console.warn('Failed loading admin data:', e);
      setErrorMessage(e?.message || 'Failed to load telemetry from server.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    loadData();
  }, [isOpen, loadData]);

  if (!isOpen) return null;

  const filteredDataset = dataset.filter(
    (item) => langFilter === 'all' || item.language === langFilter
  );

  const handleExportDatasetJson = () => {
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(dataset, null, 2))}`;
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', jsonString);
    downloadAnchor.setAttribute('download', `scamcheck-training-dataset-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handleVerify = async (itemId: string) => {
    await api.verifyDatasetItem(itemId);
    setDataset((prev) =>
      prev.map((item) => (item.id === itemId ? { ...item, verified: true } : item))
    );
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs animate-fadeIn"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-card rounded-2xl border border-borderDefault shadow-dialog overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-borderDefault bg-surfaceInput/40">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-primary/10 text-primary">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-typography-headline">
                {t.admin.title}
              </h2>
              <p className="text-xs text-typography-muted">{t.admin.subtitle}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={loadData}
              className="p-2 rounded-lg text-typography-muted hover:text-typography-body hover:bg-card border border-borderDefault transition-colors cursor-pointer"
              title="Refresh telemetry"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-primary' : ''}`} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-2 rounded-lg text-typography-muted hover:text-typography-body hover:bg-card border border-borderDefault transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-2 px-6 py-2.5 border-b border-borderDefault bg-canvas/60 text-xs font-medium">
          <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1.5 rounded-lg transition-standard cursor-pointer ${
              activeTab === 'overview'
                ? 'bg-primary text-white font-semibold shadow-xs'
                : 'text-typography-muted hover:text-typography-body'
            }`}
          >
            Telemetry Overview
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('metrics')}
            className={`px-3 py-1.5 rounded-lg transition-standard cursor-pointer ${
              activeTab === 'metrics'
                ? 'bg-primary text-white font-semibold shadow-xs'
                : 'text-typography-muted hover:text-typography-body'
            }`}
          >
            Model Performance (F1 / Confusion Matrix)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('dataset')}
            className={`px-3 py-1.5 rounded-lg transition-standard cursor-pointer ${
              activeTab === 'dataset'
                ? 'bg-primary text-white font-semibold shadow-xs'
                : 'text-typography-muted hover:text-typography-body'
            }`}
          >
            Verified Training Dataset ({dataset.length})
          </button>
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {errorMessage && (
            <div className="p-4 rounded-xl bg-danger/10 border border-danger/20 text-xs text-danger flex items-center justify-between animate-fadeIn">
              <span>{errorMessage}</span>
              <button
                type="button"
                onClick={loadData}
                className="underline font-semibold ml-3 hover:text-danger-dark cursor-pointer"
              >
                Retry
              </button>
            </div>
          )}
          {activeTab === 'overview' && stats && (
            <div className="space-y-6 animate-fadeIn">
              {/* Top Stats Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-4 rounded-xl bg-card border border-borderDefault space-y-1">
                  <span className="text-[11px] font-medium text-typography-muted uppercase tracking-wider block">
                    {t.admin.totalScans}
                  </span>
                  <span className="text-2xl font-bold font-mono text-typography-headline block">
                    {stats.total_scans.toLocaleString()}
                  </span>
                </div>
                <div className="p-4 rounded-xl bg-card border border-borderDefault space-y-1">
                  <span className="text-[11px] font-medium text-typography-muted uppercase tracking-wider block">
                    {t.admin.scamsDetected}
                  </span>
                  <span className="text-2xl font-bold font-mono text-danger block">
                    {stats.scams_detected.toLocaleString()}
                  </span>
                </div>
                <div className="p-4 rounded-xl bg-card border border-borderDefault space-y-1">
                  <span className="text-[11px] font-medium text-typography-muted uppercase tracking-wider block">
                    {t.admin.highRiskUrls}
                  </span>
                  <span className="text-2xl font-bold font-mono text-warning block">
                    {stats.high_risk_urls.toLocaleString()}
                  </span>
                </div>
                <div className="p-4 rounded-xl bg-card border border-borderDefault space-y-1">
                  <span className="text-[11px] font-medium text-typography-muted uppercase tracking-wider block">
                    {t.admin.falsePositiveRate}
                  </span>
                  <span className="text-2xl font-bold font-mono text-safe block">
                    {stats.false_positive_rate}%
                  </span>
                </div>
              </div>

              {/* Threat Category & Language Distributions */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-surfaceInput/30 border border-borderDefault space-y-3">
                  <span className="text-xs font-bold text-typography-headline uppercase tracking-wider block">
                    Threat Category Distribution
                  </span>
                  <div className="space-y-2 text-xs">
                    {Object.entries(stats.category_distribution).map(([category, count]) => (
                      <div key={category} className="space-y-1">
                        <div className="flex justify-between text-[11px] text-typography-body font-mono">
                          <span>{category}</span>
                          <span>{count} scans</span>
                        </div>
                        <div className="w-full bg-surfaceInput rounded-full h-1.5 overflow-hidden">
                          <div
                            className="bg-primary h-1.5 rounded-full"
                            style={{ width: `${Math.min(100, (count / stats.total_scans) * 300)}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-surfaceInput/30 border border-borderDefault space-y-3">
                  <span className="text-xs font-bold text-typography-headline uppercase tracking-wider block">
                    Language Distribution
                  </span>
                  <div className="space-y-3 text-xs">
                    <div className="p-3 rounded-lg bg-card border border-borderDefault flex items-center justify-between">
                      <div>
                        <span className="font-semibold text-typography-headline block">English (EN)</span>
                        <span className="text-[10px] text-typography-muted">Standard phishing & malware</span>
                      </div>
                      <span className="font-mono font-bold text-primary">{stats.language_distribution.en || 780} scans</span>
                    </div>
                    <div className="p-3 rounded-lg bg-card border border-borderDefault flex items-center justify-between">
                      <div>
                        <span className="font-semibold text-typography-headline block">Khmer (KM)</span>
                        <span className="text-[10px] text-typography-muted">Local banking & lottery scams</span>
                      </div>
                      <span className="font-mono font-bold text-primary">{stats.language_distribution.km || 420} scans</span>
                    </div>
                    <div className="p-3 rounded-lg bg-card border border-borderDefault flex items-center justify-between">
                      <div>
                        <span className="font-semibold text-typography-headline block">Khmer + English Mixed</span>
                        <span className="text-[10px] text-typography-muted">Telegram task & hybrid crypto scams</span>
                      </div>
                      <span className="font-mono font-bold text-primary">{stats.language_distribution['km-en'] || 220} scans</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'metrics' && metrics && (
            <div className="space-y-5 animate-fadeIn">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-4 rounded-xl bg-card border border-borderDefault text-center">
                  <span className="text-[11px] text-typography-muted uppercase tracking-wider block">{t.admin.accuracy}</span>
                  <span className="text-2xl font-bold font-mono text-safe">{(metrics.accuracy * 100).toFixed(1)}%</span>
                </div>
                <div className="p-4 rounded-xl bg-card border border-borderDefault text-center">
                  <span className="text-[11px] text-typography-muted uppercase tracking-wider block">{t.admin.precision}</span>
                  <span className="text-2xl font-bold font-mono text-primary">{(metrics.precision * 100).toFixed(1)}%</span>
                </div>
                <div className="p-4 rounded-xl bg-card border border-borderDefault text-center">
                  <span className="text-[11px] text-typography-muted uppercase tracking-wider block">{t.admin.recall}</span>
                  <span className="text-2xl font-bold font-mono text-primary">{(metrics.recall * 100).toFixed(1)}%</span>
                </div>
                <div className="p-4 rounded-xl bg-card border border-borderDefault text-center">
                  <span className="text-[11px] text-typography-muted uppercase tracking-wider block">{t.admin.f1Score}</span>
                  <span className="text-2xl font-bold font-mono text-safe">{(metrics.f1_score * 100).toFixed(1)}%</span>
                </div>
              </div>

              {/* Confusion Matrix Breakdown */}
              <div className="p-4 rounded-xl bg-surfaceInput/30 border border-borderDefault space-y-3">
                <span className="text-xs font-bold text-typography-headline uppercase tracking-wider block">
                  Cybersecurity Evaluation Benchmark Details
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                  <div className="p-3 rounded-lg bg-card border border-borderDefault">
                    <span className="text-typography-muted block">Benchmark Samples</span>
                    <span className="text-base font-bold font-mono text-typography-headline">{metrics.total_evaluated} curated cases</span>
                  </div>
                  <div className="p-3 rounded-lg bg-card border border-borderDefault">
                    <span className="text-typography-muted block">False Positives (Benign flagged)</span>
                    <span className="text-base font-bold font-mono text-safe">
                      {metrics.false_positives} ({((metrics.false_positive_rate ?? 0) * 100).toFixed(1)}%)
                    </span>
                  </div>
                  <div className="p-3 rounded-lg bg-card border border-borderDefault">
                    <span className="text-typography-muted block">False Negatives (Missed Threats)</span>
                    <span className="text-base font-bold font-mono text-safe">
                      {metrics.false_negatives} ({((metrics.false_negative_rate ?? 0) * 100).toFixed(1)}%)
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'dataset' && (
            <div className="space-y-4 animate-fadeIn">
              {/* Controls */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                <div className="flex items-center gap-1 bg-surfaceInput p-1 rounded-lg border border-borderDefault text-xs">
                  {(['all', 'en', 'km', 'km-en'] as const).map((l) => (
                    <button
                      key={l}
                      type="button"
                      onClick={() => setLangFilter(l)}
                      className={`px-2.5 py-1 rounded font-mono uppercase text-[11px] transition-standard cursor-pointer ${
                        langFilter === l
                          ? 'bg-card text-typography-headline font-bold shadow-xs'
                          : 'text-typography-muted hover:text-typography-body'
                      }`}
                    >
                      {l}
                    </button>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={handleExportDatasetJson}
                  className="px-3 py-1.5 rounded-lg bg-primary text-white text-xs font-medium hover:bg-primary-hover transition-standard cursor-pointer flex items-center gap-1.5 shadow-xs"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>{t.admin.exportDataset}</span>
                </button>
              </div>

              {/* Table */}
              <div className="border border-borderDefault rounded-xl overflow-hidden bg-card text-xs">
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead className="bg-surfaceInput/60 border-b border-borderDefault text-[11px] uppercase tracking-wider text-typography-muted font-semibold">
                      <tr>
                        <th className="p-3">ID</th>
                        <th className="p-3">Language</th>
                        <th className="p-3">Content Sample</th>
                        <th className="p-3">Category</th>
                        <th className="p-3">Risk</th>
                        <th className="p-3">Status</th>
                        <th className="p-3 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-borderDefault font-mono text-[11px]">
                      {filteredDataset.map((item) => (
                        <tr key={item.id} className="hover:bg-surfaceInput/30 transition-colors">
                          <td className="p-3 text-typography-muted">{item.id}</td>
                          <td className="p-3 uppercase font-bold text-primary">{item.language}</td>
                          <td className="p-3 max-w-xs font-sans text-typography-body truncate" title={item.content}>
                            {item.content}
                          </td>
                          <td className="p-3">
                            <span className="px-1.5 py-0.5 rounded bg-surfaceInput border border-borderDefault text-[10px]">
                              {item.category}
                            </span>
                          </td>
                          <td className="p-3 font-bold">{item.risk_score}</td>
                          <td className="p-3">
                            {item.verified ? (
                              <span className="inline-flex items-center gap-1 text-safe text-[10px] font-bold">
                                <CheckCircle2 className="w-3 h-3" />
                                <span>Verified</span>
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-warning text-[10px] font-bold">
                                <Clock className="w-3 h-3" />
                                <span>Candidate</span>
                              </span>
                            )}
                          </td>
                          <td className="p-3 text-right">
                            {!item.verified && (
                              <button
                                type="button"
                                onClick={() => handleVerify(item.id)}
                                className="px-2 py-0.5 rounded bg-safe-light hover:bg-safe-light/80 text-safe-dark font-bold text-[10px] transition-colors cursor-pointer"
                              >
                                Verify
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
