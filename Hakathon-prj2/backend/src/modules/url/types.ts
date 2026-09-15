import { DetectionItem } from '../../types';

export type ImpersonationType =
  | 'typosquatting'
  | 'lookalike'
  | 'combisquatting'
  | 'subdomain_spoof'
  | 'homoglyph';

export interface BrandImpersonationMatch {
  detected: boolean;
  targetedBrand?: string;
  impersonationType?: ImpersonationType;
  matchedHostname?: string;
  baseDomain?: string;
  levenshteinDistance?: number;
  similarityScore?: number;
  description?: string;
}

export interface UrlMetadata {
  rawUrl: string;
  normalizedUrl: string;
  protocol: string;
  isHttps: boolean;
  hostname: string;
  domain: string;
  baseDomain: string;
  subdomains: string[];
  subdomainCount: number;
  tld: string;
  port?: string;
  pathname: string;
  search: string;
  hash: string;
  isIpAddress: boolean;
  ipAddress?: string;
  isObfuscatedIp: boolean;
  isShortener: boolean;
  shortenerService?: string;
  isPunycode: boolean;
  punycodeDecoded?: string;
  hasUserinfo: boolean;
  userinfoCredentials?: string;
}

export interface StructuralAnalysis {
  entropyScore: number;
  hyphenCount: number;
  digitRatio: number;
  subdomainDepth: number;
  isExcessiveSubdomains: boolean;
  hasCredentialPath: boolean;
  credentialKeywordsFound: string[];
  hasExecutablePayload: boolean;
  executableExtension?: string;
  hasOpenRedirectParam: boolean;
  openRedirectParamsFound: string[];
  hasSensitiveQueryParams: boolean;
  sensitiveQueryParamsFound: string[];
  hasPathTraversal: boolean;
}

export interface NetworkProbeResult {
  probed: boolean;
  statusCode?: number;
  hasRedirects: boolean;
  redirectCount: number;
  redirectChain: string[];
  finalDestinationUrl?: string;
  crossDomainRedirect: boolean;
  targetDomainChanged: boolean;
  ssrfSafe: boolean;
  ssrfBlockedReason?: string;
  resolvedIp?: string;
  latencyMs?: number;
  errorMessage?: string;
}

export interface UrlThreatIndicators {
  summary: string;
  indicators: string[];
  riskFactors: string[];
  safeFactors: string[];
  details: {
    metadata: UrlMetadata;
    brandImpersonation: BrandImpersonationMatch;
    structural: StructuralAnalysis;
    networkProbe: NetworkProbeResult;
    threatIntelMatched: boolean;
    threatIntelProvider?: string;
  };
}

export interface UrlIntelligenceResult {
  url: string;
  normalizedUrl: string;
  compositeScore: number;
  severity: 'safe' | 'low' | 'medium' | 'high' | 'critical' | 'needs_review';
  confidence: number;
  threatCategory: string;
  indicators: string[];
  detections: DetectionItem[];
  brandImpersonation: BrandImpersonationMatch;
  metadata: UrlMetadata;
  structural: StructuralAnalysis;
  networkProbe: NetworkProbeResult;
  evidence: UrlThreatIndicators;
  recommendedAction: string;
}
