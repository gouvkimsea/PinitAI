import fs from 'fs';
import path from 'path';
import { calculateFileHashes } from '../../scanners/hash/hashScanner';
import { analyzeMagicBytes } from '../../scanners/file/magicBytes';
import { analyzeFileStatically } from '../../scanners/file/staticAnalyzer';
import { scanWithClamAV } from '../../scanners/antivirus/clamavScanner';
import { threatIntel } from '../../scanners/threatIntel/threatIntelProvider';
import {
  FILE_SECURITY_POLICY,
  sanitizeUploadFilename,
  inspectDoubleExtension,
} from './fileSecurityPolicy';
import { quarantineStorage } from './quarantineStorage';
import { SecureFileLogger } from './fileLogger';
import {
  SecureFileAnalysisResult,
  FileRiskClassification,
  FileHashes,
} from './types';
import { DetectionItem } from '../../types';
import { metricsCollector } from '../monitoring/metricsCollector';

export class SecureFileAnalyzer {
  private static instance: SecureFileAnalyzer | null = null;

  public static getInstance(): SecureFileAnalyzer {
    if (!SecureFileAnalyzer.instance) {
      SecureFileAnalyzer.instance = new SecureFileAnalyzer();
    }
    return SecureFileAnalyzer.instance;
  }

  /**
   * Performs malware-safe static sandboxed analysis on an uploaded file.
   *
   * SECURITY ENFORCEMENT:
   * - NEVER executes the file or spawns shell processes.
   * - Uses bounded read streams and header probes to prevent memory exhaustion.
   * - Enforces a strict 15-second timeout circuit breaker.
   * - Securely deletes the quarantined file upon completion or failure.
   */
  public async analyze(
    filePath: string,
    originalName: string,
    declaredMime: string,
    options?: { quarantineId?: string; autoCleanup?: boolean }
  ): Promise<SecureFileAnalysisResult> {
    const startTime = Date.now();
    const autoCleanup = options?.autoCleanup ?? true;
    const quarantineId = options?.quarantineId || `quar_${Date.now()}`;

    // Apply strict non-executable permissions to the file
    await quarantineStorage.restrictPermissions(filePath);

    try {
      // Wrap complete analysis in a processing timeout race
      const analysisPromise = this.executeSandboxedInspection(
        filePath,
        originalName,
        declaredMime,
        quarantineId,
        startTime
      );

      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new Error(`File analysis timed out after ${FILE_SECURITY_POLICY.PROCESSING_TIMEOUT_MS}ms.`));
        }, FILE_SECURITY_POLICY.PROCESSING_TIMEOUT_MS);
      });

      const result = await Promise.race([analysisPromise, timeoutPromise]);
      return result;
    } finally {
      if (autoCleanup) {
        await quarantineStorage.secureDelete(filePath);
        SecureFileLogger.logCleanup(filePath);
      }
    }
  }

  /**
   * Internal static multi-engine inspection implementation.
   */
  private async executeSandboxedInspection(
    filePath: string,
    originalName: string,
    declaredMime: string,
    quarantineId: string,
    startTime: number
  ): Promise<SecureFileAnalysisResult> {
    if (!fs.existsSync(filePath)) {
      throw new Error(`Quarantined file not found at path: ${path.basename(filePath)}`);
    }

    const stats = await fs.promises.stat(filePath);
    const fileSize = stats.size;
    const sanitizedName = sanitizeUploadFilename(originalName);
    const rawExtension = path.extname(sanitizedName).replace('.', '').toLowerCase();

    const detectedIndicators: string[] = [];
    const allDetections: DetectionItem[] = [];
    let accumulatedScore = 0;

    // -----------------------------------------------------------------------
    // Engine 1: Cryptographic Hashing (SHA-256, SHA-1, MD5)
    // -----------------------------------------------------------------------
    const hashes: FileHashes = await calculateFileHashes(filePath);

    // -----------------------------------------------------------------------
    // Engine 3: Double Extension Deception Detection
    // -----------------------------------------------------------------------
    const doubleExt = inspectDoubleExtension(sanitizedName);
    if (doubleExt.isDoubleExtension) {
      accumulatedScore = Math.max(accumulatedScore, 85);
      const indicator = `Dangerous Double Extension: Disguised as benign .${doubleExt.disguisedExtension} document, but final executable extension is .${doubleExt.actualExtension}.`;
      detectedIndicators.push(indicator);
      allDetections.push({
        engine: 'ExtensionGuard',
        category: 'deceptive_extension',
        severity: 'critical',
        ruleId: 'EXT-DOUBLE-01',
        title: 'Deceptive Double Extension',
        description: indicator,
      });
    }

    // -----------------------------------------------------------------------
    // Parallelized Multi-Engine Inspection: Magic Bytes, Static, ClamAV, ThreatIntel
    // -----------------------------------------------------------------------
    const [magicResult, staticResult, avResult, hashIntel] = await Promise.all([
      analyzeMagicBytes(filePath, rawExtension, declaredMime),
      analyzeFileStatically(filePath, sanitizedName, fileSize),
      scanWithClamAV(filePath),
      threatIntel.checkHash(hashes.sha256),
    ]);

    // Engine 2 Findings: Magic Bytes & Extension Spoofing
    for (const det of magicResult.detections) {
      allDetections.push(det);
      detectedIndicators.push(`${det.title}: ${det.description}`);
      accumulatedScore += this.severityToScore(det.severity);
    }
    if (magicResult.isMismatch) {
      accumulatedScore = Math.max(accumulatedScore, 75);
      const indicator = `Deceptive Extension Spoofing: Declared as .${rawExtension} (${declaredMime}), but file headers confirm true binary signature is ${magicResult.detectedMimeType} (${magicResult.detectedType}).`;
      detectedIndicators.push(indicator);
      SecureFileLogger.logSecurityWarning({
        quarantineId,
        fileName: sanitizedName,
        warning: indicator,
      });
    }

    // Engine 4 Findings: Static Heuristics & Zip Bomb Checks
    for (const det of staticResult.detections) {
      allDetections.push(det);
      detectedIndicators.push(`${det.title}: ${det.description}`);
      accumulatedScore += this.severityToScore(det.severity);
    }
    if (staticResult.archiveDetails?.isZipBombRisk) {
      accumulatedScore = Math.max(accumulatedScore, 85);
      detectedIndicators.push('Resource Exhaustion Attack: Archive triggers zip bomb thresholds.');
    }

    // Engine 5 Findings: Antivirus Scan
    if (avResult.isInfected) {
      accumulatedScore = Math.max(accumulatedScore, 95);
      for (const det of avResult.detections) {
        allDetections.push(det);
        detectedIndicators.push(`Antivirus Malicious Flag [${avResult.engine}]: ${det.title}`);
      }
    }

    // Engine 6 Findings: Threat Intelligence Hash Lookup
    if (hashIntel && hashIntel.detections && hashIntel.detections.length > 0) {
      accumulatedScore = Math.max(accumulatedScore, 90);
      for (const det of hashIntel.detections) {
        allDetections.push(det);
        detectedIndicators.push(`Threat Intelligence Hit (${hashIntel.provider}): ${det.title}`);
      }
    }

    // -----------------------------------------------------------------------
    // Composite Scoring & Classification
    // -----------------------------------------------------------------------
    // If it is a known executable or script with zero anomalies, assign mild baseline
    if (magicResult.isExecutable && accumulatedScore === 0) {
      accumulatedScore = 30; // Unsigned or unverified executable
      detectedIndicators.push('Executable Binary: Contains machine code or script execution vectors.');
    }

    const riskScore = Math.min(100, accumulatedScore);
    const classification = this.scoreToClassification(riskScore);
    const durationMs = Date.now() - startTime;

    const fileType = magicResult.detectedType || (rawExtension ? `${rawExtension.toUpperCase()} File` : 'Binary File');

    // Generate clear, actionable security recommendation
    let recommendedAction = 'No malicious indicators or file format anomalies detected. Safe to open.';
    if (classification === 'Critical Risk') {
      recommendedAction = 'CRITICAL MALWARE ALERT: File contains confirmed malicious signatures, disguised executables, or exploit scripts. Do NOT open or execute this file. Delete immediately.';
    } else if (classification === 'High Risk') {
      recommendedAction = 'HIGH THREAT WARNING: File exhibits deceptive characteristics (e.g. double extension or obfuscated scripts). Do not open without isolated sandbox verification.';
    } else if (classification === 'Suspicious') {
      recommendedAction = 'SUSPICIOUS INDICATORS: File contains anomalous macros, embedded scripts, or unusual format structure. Exercise caution before opening.';
    } else if (classification === 'Mild Risk') {
      recommendedAction = 'MILD RISK: File contains executable structures or active content. Ensure source is trusted before running.';
    }

    const enginesEvaluated = [
      'CryptographicHashing',
      'MagicBytesInspection',
      'DoubleExtensionGuard',
      'StaticHeuristicAnalyzer',
      avResult.engine,
    ];
    if (hashIntel) enginesEvaluated.push(hashIntel.provider);

    const summary = detectedIndicators.length > 0
      ? `Identified ${detectedIndicators.length} security indicators across ${enginesEvaluated.length} static evaluation engines.`
      : `File signatures, magic bytes, and static heuristic checks verified clean.`;

    // Secure audit logging
    SecureFileLogger.logAnalysisCompleted({
      quarantineId,
      sanitizedName,
      sha256: hashes.sha256,
      fileType,
      riskScore,
      classification,
      indicatorsCount: detectedIndicators.length,
      durationMs,
    });

    const resultPayload: SecureFileAnalysisResult = {
      file_type: fileType,
      file_size: fileSize,
      detected_indicators: detectedIndicators,
      risk_score: riskScore,
      classification,
      evidence: {
        summary,
        file_hashes: hashes,
        magic_bytes: {
          detected_mime: magicResult.detectedMimeType,
          detected_type: magicResult.detectedType,
          file_header_hex: magicResult.fileHeaderHex,
          is_mime_mismatch: magicResult.isMismatch,
        },
        static_heuristics: {
          has_macro: staticResult.hasMacro,
          has_embedded_scripts: staticResult.hasEmbeddedScripts,
          is_double_extension: doubleExt.isDoubleExtension,
          is_suspicious_executable: staticResult.isSuspiciousExecutable,
          archive_details: staticResult.archiveDetails
            ? {
                total_files: staticResult.archiveDetails.totalFiles,
                suspicious_extensions_found: staticResult.archiveDetails.suspiciousExtensionsFound,
                is_zip_bomb_risk: staticResult.archiveDetails.isZipBombRisk,
              }
            : undefined,
        },
        antivirus: {
          engine: avResult.engine,
          is_clean: !avResult.isInfected,
          threat_found: avResult.detections[0]?.title,
        },
        threat_intelligence: hashIntel
          ? {
              provider: hashIntel.provider,
              is_known_malicious: (hashIntel.detections?.length || 0) > 0,
              reputation_score: hashIntel.reputationScore,
            }
          : undefined,
        engines_evaluated: enginesEvaluated,
      },
      recommended_action: recommendedAction,
      sanitized_name: sanitizedName,
      quarantine_id: quarantineId,
      execution_time_ms: durationMs,
    };

    metricsCollector.recordFileAnalysis(durationMs, false);
    return resultPayload;
  }

  private severityToScore(severity: string): number {
    switch (severity) {
      case 'critical':
        return 45;
      case 'high':
        return 30;
      case 'medium':
        return 15;
      case 'low':
      default:
        return 5;
    }
  }

  private scoreToClassification(score: number): FileRiskClassification {
    if (score >= 81) return 'Critical Risk';
    if (score >= 61) return 'High Risk';
    if (score >= 41) return 'Suspicious';
    if (score >= 21) return 'Mild Risk';
    return 'Low Risk';
  }
}

export const secureFileAnalyzer = SecureFileAnalyzer.getInstance();
