export type FileThreatSeverity = 'safe' | 'low' | 'medium' | 'high' | 'critical';

export type FileRiskClassification =
  | 'Low Risk'
  | 'Mild Risk'
  | 'Suspicious'
  | 'High Risk'
  | 'Critical Risk';

export interface FileHashes {
  sha256: string;
  sha1: string;
  md5: string;
}

export interface QuarantineFileRecord {
  quarantineId: string;
  originalName: string;
  sanitizedName: string;
  quarantinePath: string;
  sizeBytes: number;
  mimeType: string;
  createdAt: Date;
}

export interface FileValidationResult {
  valid: boolean;
  error?: {
    code: string;
    message: string;
    httpStatus: number;
  };
  sanitizedName: string;
  extension: string;
  declaredMime: string;
  fileSize: number;
}

export interface SecureFileAnalysisResult {
  // Exact 7 required top-level fields
  file_type: string;
  file_size: number;
  detected_indicators: string[];
  risk_score: number; // 0 to 100
  classification: FileRiskClassification;
  evidence: {
    summary: string;
    file_hashes: FileHashes;
    magic_bytes: {
      detected_mime: string;
      detected_type: string;
      file_header_hex: string;
      is_mime_mismatch: boolean;
    };
    static_heuristics: {
      has_macro: boolean;
      has_embedded_scripts: boolean;
      is_double_extension: boolean;
      is_suspicious_executable: boolean;
      archive_details?: {
        total_files: number;
        suspicious_extensions_found: string[];
        is_zip_bomb_risk: boolean;
      };
    };
    antivirus: {
      engine: string;
      is_clean: boolean;
      threat_found?: string;
    };
    threat_intelligence?: {
      provider: string;
      is_known_malicious: boolean;
      reputation_score: number;
    };
    engines_evaluated: string[];
  };
  recommended_action: string;

  // Supplementary tracking metadata
  sanitized_name: string;
  quarantine_id: string;
  execution_time_ms: number;
}
