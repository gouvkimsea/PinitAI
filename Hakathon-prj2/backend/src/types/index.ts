export type ScanType = 'FILE' | 'URL';

export type ScanStatus = 'QUEUED' | 'PROCESSING' | 'COMPLETED' | 'FAILED';

export type ThreatLevel = 
  | 'SAFE'
  | 'LOW_RISK'
  | 'SUSPICIOUS'
  | 'HIGH_RISK'
  | 'MALICIOUS'
  | 'UNKNOWN';

export type ThreatConfidence = 'LOW' | 'MEDIUM' | 'HIGH';

export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

export interface DetectionItem {
  engine: string;
  category: string;
  severity: SeverityLevel;
  ruleId: string;
  title: string;
  description: string;
  details?: Record<string, unknown>;
}

export interface FileScanMetadata {
  originalName: string;
  sanitizedName: string;
  extension: string;
  mimeType: string;
  detectedMimeType?: string;
  sizeBytes: number;
  hashes: {
    sha256: string;
    sha1: string;
    md5: string;
  };
  fileHeaderHex?: string;
  hasMacro?: boolean;
  hasEmbeddedScripts?: boolean;
  isExecutableDisguised?: boolean;
  archiveDetails?: {
    totalFiles: number;
    suspiciousExtensionsFound: string[];
    isZipBombRisk: boolean;
  };
}

export interface UrlScanMetadata {
  url: string;
  normalizedUrl: string;
  domain: string;
  ipAddress?: string;
  isHttps: boolean;
  hasRedirects: boolean;
  redirectCount: number;
  redirectChain: string[];
  statusCode?: number;
  domainAgeDays?: number;
  isPunycode: boolean;
  suspiciousKeywordsFound: string[];
  entropyScore?: number;
}

export interface EngineResult {
  engineName: string;
  isClean: boolean;
  isMalicious: boolean;
  isSuspicious: boolean;
  detections: DetectionItem[];
  rawDetails?: Record<string, unknown>;
}

export interface AggregatedScore {
  threatLevel: ThreatLevel;
  riskScore: number; // 0 to 100
  threatConfidence: ThreatConfidence;
  summary: string;
  totalEngines: number;
  maliciousEngines: number;
  suspiciousEngines: number;
  cleanEngines: number;
  safeFactors: string[];
  recommendations: string[];
  allDetections: DetectionItem[];
}

export type UserRole = 'user' | 'admin' | 'analyst';

export interface AuthUser {
  id: string;
  email: string;
  role: UserRole;
  apiKey?: string | null;
  apiKeyHash?: string | null;
}

