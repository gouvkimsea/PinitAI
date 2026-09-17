export type ScanTab = 'file' | 'url' | 'qr' | 'message';

export interface ThreatAnalysisResult {
  id: string;
  type: ScanTab;
  targetName: string;
  riskScore: number; // 0 - 100
  verdict: 'safe' | 'suspicious' | 'malicious';
  title: string;
  summary: string;
  signals: {
    label: string;
    severity: 'low' | 'medium' | 'high';
    description: string;
  }[];
  recommendations: string[];
  scanDurationMs: number;
  timestamp: string;
}

export interface PricingPlan {
  id: string;
  name: string;
  tagline: string;
  price: string;
  period: string;
  featured?: boolean;
  features: string[];
  ctaText: string;
}
