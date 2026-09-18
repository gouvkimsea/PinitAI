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
  category?: 'banking' | 'government' | 'shipping' | 'tech' | 'crypto' | 'social';
  impersonationType?: ImpersonationType;
  matchedHostname?: string;
  baseDomain?: string;
  levenshteinDistance?: number;
  similarityScore?: number;
  description?: string;
  lookalikeSubstitution?: string;
}

export interface DomainAgeInfo {
  evaluated: boolean;
  domainAgeDays?: number;
  isNewDomain?: boolean; // <= 30 days
  creationDate?: string;
  expirationDate?: string;
  registrar?: string;
  privacyProtected?: boolean;
  cached?: boolean;
  error?: string;
}

export interface TlsInfo {
  isHttps: boolean;
  protocol?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  isSelfSigned?: boolean;
  isExpired?: boolean;
  daysUntilExpiration?: number;
}

export interface ContentSignals {
  evaluated: boolean;
  pageTitle?: string;
  titleBrandMismatch?: boolean;
  matchedBrandInTitle?: string;
  hasLoginForm?: boolean;
  hasPasswordInput?: boolean;
  hasCreditCardInput?: boolean;
  hasMetaRefresh?: boolean;
  metaRefreshTarget?: string;
  isSuspiciousLoginDrop?: boolean;
}

export interface UrlMetadata {
  rawUrl: string;
  normalizedUrl: string;
  protocol: string;
  isHttps: boolean;
  isDangerousScheme?: boolean;
  schemeViolation?: string;
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
  normalizedIp?: string;
  isObfuscatedIp: boolean;
  isShortener: boolean;
  shortenerService?: string;
  isPunycode: boolean;
  punycodeDecoded?: string;
  isMixedScript?: boolean;
  isLookalike?: boolean;
  lookalikeDetails?: string;
  hasUserinfo: boolean;
  userinfoCredentials?: string;
  isTopDomainWhitelist?: boolean;
}

export interface StructuralAnalysis {
  entropyScore: number;
  hyphenCount: number;
  digitRatio: number;
  subdomainDepth: number;
  isExcessiveSubdomains: boolean;
  hasCredentialPath: boolean;
  credentialKeywordsFound: string[];
  hasPaymentPath?: boolean;
  paymentKeywordsFound?: string[];
  hasLoginPath?: boolean;
  loginKeywordsFound?: string[];
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
  bodySnippet?: string;
  tlsInfo?: TlsInfo;
  contentSignals?: ContentSignals;
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
    domainAge?: DomainAgeInfo;
    tlsInfo?: TlsInfo;
    contentSignals?: ContentSignals;
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
  domainAge?: DomainAgeInfo;
  tlsInfo?: TlsInfo;
  contentSignals?: ContentSignals;
  evidence: UrlThreatIndicators;
  recommendedAction: string;
}
