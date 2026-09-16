import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import prisma from '../database/client';
import { inputNormalizer } from './normalization';
import { detectorRegistry } from './registry/detectorRegistry';
import { evidenceCollector } from './evidence/evidenceCollector';
import { riskEngine } from '../modules/risk/riskEngine';
import { explanationEngine } from '../modules/ai/explanationEngine';
import { PipelineInput, PipelineContext, PipelineFinalResult } from './types';
import IORedis from 'ioredis';
import { config } from '../config';
import { logger } from '../utils/logger';
import { LruCache } from '../utils/lruCache';
import { metricsCollector } from '../modules/monitoring/metricsCollector';

export class DetectionPipeline {
  private duplicateCache = new LruCache<string, PipelineFinalResult>({
    maxSize: 1000,
    defaultTtlMs: 10 * 60 * 1000, // 10 minutes cache freshness
  });
  private redisClient: IORedis | null = null;

  constructor() {
    if (config.redisUrl && config.redisUrl.trim().length > 0) {
      try {
        this.redisClient = new IORedis(config.redisUrl, {
          lazyConnect: true,
          enableOfflineQueue: false,
          maxRetriesPerRequest: 1,
        });
        this.redisClient.connect().catch((err) => {
          logger.warn('DetectionPipeline Redis connection failed, using in-memory cache', { error: err.message });
          this.redisClient = null;
        });
      } catch {
        this.redisClient = null;
      }
    }
  }

  public getCacheStats() {
    return this.duplicateCache.getStats();
  }

  public clearCache(): void {
    this.duplicateCache.clear();
  }

  async analyze(input: PipelineInput): Promise<PipelineFinalResult> {
    return this.execute(input);
  }

  /**
   * Executes the full multi-layer scam detection pipeline:
   * User Input → Validation → Normalization → Multiple Detectors → Evidence Collection → Risk Engine → AI Explanation → Final Result
   */
  async execute(input: PipelineInput): Promise<PipelineFinalResult> {
    const startTime = Date.now();
    const scanId = input.scanId || uuidv4();

    // Fast deduplication check for identical targets
    const rawTarget = (input.rawContent || input.originalFileName || '').trim();
    const targetHash = rawTarget
      ? crypto.createHash('sha256').update(rawTarget).digest('hex')
      : null;

    if (targetHash && !input.metadata?.bypassCache && !input.metadata?.noCache) {
      let cached = this.duplicateCache.get(targetHash);
      if (!cached && this.redisClient && this.redisClient.status === 'ready') {
        try {
          const raw = await this.redisClient.get(`pinit:dedup:${targetHash}`);
          if (raw) {
            cached = JSON.parse(raw);
            if (cached) this.duplicateCache.set(targetHash, cached);
          }
        } catch {
          // Graceful fallback on redis read error
        }
      }
      if (cached) {
        logger.info('Duplicate analysis cache hit — returning cached scan result', {
          scanId,
          cachedScanId: cached.scan_id,
          targetHash: targetHash.slice(0, 16),
        });
        if (input.type === 'URL') {
          metricsCollector.recordUrlAnalysis(0, true);
        }
        return {
          ...cached,
          id: scanId,
          scan_id: scanId,
          cached: true,
          created_at: new Date().toISOString(),
        };
      }
    }

    const context: PipelineContext = {
      scanId,
      userId: input.userId,
      startTime,
    };

    logger.info('Initiating multi-layer scam detection pipeline', {
      scanId,
      type: input.type,
      targetPreview: (input.rawContent || input.originalFileName || '').slice(0, 60),
    });

    // 1 & 2. Validation & Normalization Layer
    const normalized = inputNormalizer.normalize(input);

    // 3. Multiple Detectors Selection
    const applicableDetectors = detectorRegistry.getDetectorsFor(normalized.type);
    logger.debug(`Selected ${applicableDetectors.length} active detectors for type ${normalized.type}`);

    // 4. Concurrent Evidence Collection
    const evidenceCollection = await evidenceCollector.collect(applicableDetectors, normalized, context);

    // 5. Centralized Risk Engine Evaluation
    const riskResult = riskEngine.evaluateEvidence(evidenceCollection);

    // Determine primary threat category
    const primaryCategory = evidenceCollection.detectedThreatCategories[0] ||
      (riskResult.threatLevel === 'SAFE' ? 'SAFE' : 'SUSPICIOUS_TARGET');

    // 6. AI Explanation Layer
    const isKm = normalized.detectedLanguage === 'km' || normalized.detectedLanguage === 'km-en';
    const explanation = await explanationEngine.generateStructuredExplanation({
      targetType: input.type,
      threatCategory: primaryCategory,
      riskScore: riskResult.riskScore,
      classification: riskResult.classification,
      threatLevel: riskResult.threatLevel,
      confidenceScore: riskResult.confidenceScore,
      language: normalized.detectedLanguage || 'en',
      indicators: evidenceCollection.indicators,
      detectorResults: evidenceCollection.detectorResults,
      rawContentSnippet: (input.rawContent || normalized.raw || '').slice(0, 100),
      evidenceBreakdown: riskResult.evidenceBreakdown,
    });

    const isHigh = riskResult.riskScore >= 60;
    const isSuspicious = riskResult.riskScore >= 40 && riskResult.riskScore < 60;

    let title = 'Likely Safe — No Obvious Threats Detected';
    if (isHigh) {
      title = isKm
        ? 'ការគំរាមកំហែងកម្រិតខ្ពស់ — រកឃើញសញ្ញាបោកប្រាស់ច្បាស់លាស់'
        : `High Risk Threat Detected (${primaryCategory})`;
    } else if (isSuspicious) {
      title = isKm
        ? 'គួរឱ្យសង្ស័យ — រកឃើញភាពមិនប្រក្រតី'
        : `Suspicious Activity Flagged (${primaryCategory})`;
    }

    // 7. Map Detection Signals for DB & Response
    const signals: Array<{
      id: string;
      category: string;
      severity: 'low' | 'medium' | 'high';
      title: string;
      description: string;
    }> = [];

    for (const det of evidenceCollection.detectorResults) {
      if (det.score > 0) {
        signals.push({
          id: `${det.detector_name}-${signals.length + 1}`,
          category: det.detector_type,
          severity: det.severity === 'critical' ? 'high' : (det.severity as 'low' | 'medium' | 'high'),
          title: `[${det.detector_name}] ${det.evidence.summary}`,
          description: det.evidence.indicators.join('; ') || det.evidence.summary,
        });
      }
    }

    // 8. Relational Database Persistence
    const target = (input.rawContent || input.originalFileName || normalized.raw || 'Scam Analysis Target').slice(0, 255);
    const dbTargetHash = targetHash || (input.rawContent || input.originalFileName || normalized.raw
      ? crypto.createHash('sha256').update(input.rawContent || input.originalFileName || normalized.raw).digest('hex')
      : null);

    const scanType = input.type === 'TEXT' ? 'MESSAGE' : input.type;
    const scanData = {
      userId: input.userId || null,
      type: scanType,
      target,
      targetHash: dbTargetHash,
      status: 'COMPLETED' as const,
      riskLevel: riskResult.threatLevel,
      riskScore: riskResult.riskScore,
      threatConfidence: (riskResult.confidenceScore >= 75 ? 'HIGH' : 'MEDIUM') as 'HIGH' | 'MEDIUM',
      threatCategory: primaryCategory,
      scanDurationMs: Date.now() - startTime,
      completedAt: new Date(),
    };

    try {
      await prisma.scan.upsert({
        where: { id: scanId },
        create: {
          id: scanId,
          ...scanData,
          scanResult: {
            create: {
              summary: explanation.summary,
              totalEngines: evidenceCollection.totalDetectorsRan,
              maliciousEngines: evidenceCollection.maliciousCount,
              suspiciousEngines: evidenceCollection.suspiciousCount,
              cleanEngines: evidenceCollection.cleanCount,
              safeFactors: JSON.stringify(explanation.safe_factors),
              recommendations: JSON.stringify(explanation.recommended_actions),
            },
          },
          evidenceRecord: {
            create: {
              summary: explanation.summary,
              indicators: JSON.stringify(evidenceCollection.indicators),
              evidenceBreakdown: JSON.stringify(riskResult.evidenceBreakdown),
              technicalEvidence: JSON.stringify({
                language_detected: normalized.detectedLanguage,
                extracted_urls: normalized.extractedUrls,
                extracted_contacts: normalized.extractedPhoneNumbers,
                safe_factors: explanation.safe_factors,
                indicators_found: evidenceCollection.indicators,
              }),
              uncertaintyNotes: explanation.uncertainty_notes
                ? (typeof explanation.uncertainty_notes === 'string'
                    ? explanation.uncertainty_notes
                    : JSON.stringify(explanation.uncertainty_notes))
                : null,
              groundedScore: riskResult.confidenceScore,
            },
          },
          detections: {
            create: signals.map((s) => ({
              engine: s.title.split(']')[0].replace('[', '') || 'MultiLayerPipeline',
              category: s.category,
              severity: s.severity,
              ruleId: s.id,
              title: s.title,
              description: s.description,
            })),
          },
        },
        update: {
          ...scanData,
          scanResult: {
            upsert: {
              create: {
                summary: explanation.summary,
                totalEngines: evidenceCollection.totalDetectorsRan,
                maliciousEngines: evidenceCollection.maliciousCount,
                suspiciousEngines: evidenceCollection.suspiciousCount,
                cleanEngines: evidenceCollection.cleanCount,
                safeFactors: JSON.stringify(explanation.safe_factors),
                recommendations: JSON.stringify(explanation.recommended_actions),
              },
              update: {
                summary: explanation.summary,
                totalEngines: evidenceCollection.totalDetectorsRan,
                maliciousEngines: evidenceCollection.maliciousCount,
                suspiciousEngines: evidenceCollection.suspiciousCount,
                cleanEngines: evidenceCollection.cleanCount,
                safeFactors: JSON.stringify(explanation.safe_factors),
                recommendations: JSON.stringify(explanation.recommended_actions),
              },
            },
          },
          evidenceRecord: {
            upsert: {
              create: {
                summary: explanation.summary,
                indicators: JSON.stringify(evidenceCollection.indicators),
                evidenceBreakdown: JSON.stringify(riskResult.evidenceBreakdown),
                technicalEvidence: JSON.stringify({
                  language_detected: normalized.detectedLanguage,
                  extracted_urls: normalized.extractedUrls,
                  extracted_contacts: normalized.extractedPhoneNumbers,
                  safe_factors: explanation.safe_factors,
                  indicators_found: evidenceCollection.indicators,
                }),
                uncertaintyNotes: explanation.uncertainty_notes
                  ? (typeof explanation.uncertainty_notes === 'string'
                      ? explanation.uncertainty_notes
                      : JSON.stringify(explanation.uncertainty_notes))
                  : null,
                groundedScore: riskResult.confidenceScore,
              },
              update: {
                summary: explanation.summary,
                indicators: JSON.stringify(evidenceCollection.indicators),
                evidenceBreakdown: JSON.stringify(riskResult.evidenceBreakdown),
                technicalEvidence: JSON.stringify({
                  language_detected: normalized.detectedLanguage,
                  extracted_urls: normalized.extractedUrls,
                  extracted_contacts: normalized.extractedPhoneNumbers,
                  safe_factors: explanation.safe_factors,
                  indicators_found: evidenceCollection.indicators,
                }),
                uncertaintyNotes: explanation.uncertainty_notes
                  ? (typeof explanation.uncertainty_notes === 'string'
                      ? explanation.uncertainty_notes
                      : JSON.stringify(explanation.uncertainty_notes))
                  : null,
                groundedScore: riskResult.confidenceScore,
              },
            },
          },
          detections: {
            deleteMany: {},
            create: signals.map((s) => ({
              engine: s.title.split(']')[0].replace('[', '') || 'MultiLayerPipeline',
              category: s.category,
              severity: s.severity,
              ruleId: s.id,
              title: s.title,
              description: s.description,
            })),
          },
        },
      });
    } catch (dbErr) {
      logger.warn('Failed to persist pipeline result to database', { error: (dbErr as Error).message });
    }

    logger.info('Pipeline execution successfully completed', {
      scanId,
      riskScore: riskResult.riskScore,
      threatLevel: riskResult.threatLevel,
      detectorsRan: evidenceCollection.totalDetectorsRan,
      durationMs: Date.now() - startTime,
    });

    const textDetectorResult = evidenceCollection.detectorResults.find(
      (d) => d.detector_name === 'text_linguistic_detector'
    );
    const textDetails = textDetectorResult?.evidence?.details;
    const detectedPatterns: string[] = textDetails?.detected_patterns || [];
    const suspiciousPhrases: string[] = textDetails?.suspicious_phrases || [];
    const scamCategory: string = textDetails?.scam_category || primaryCategory;
    const detectedSeverity: string = textDetails?.severity ||
      (riskResult.classification === 'Critical Risk' ? 'critical' :
       riskResult.classification === 'High Risk' ? 'high' :
       riskResult.classification === 'Suspicious' ? 'medium' :
       riskResult.classification === 'Mild Risk' ? 'low' : 'safe');
    const finalRecommendedAction: string = (detectedSeverity === 'needs_review' && textDetails?.recommended_action)
      ? textDetails.recommended_action
      : riskResult.recommended_action;

    const finalResult: PipelineFinalResult = {
      id: scanId,
      scan_id: scanId,
      type: input.type,
      target,
      status: 'COMPLETED',
      risk_score: riskResult.riskScore,
      classification: detectedSeverity === 'needs_review' ? 'Needs Review' : riskResult.classification,
      confidence: riskResult.confidence,
      threat_level: riskResult.threatLevel,
      risk_level: riskResult.threatLevel.toLowerCase(),
      threat_category: primaryCategory,
      title: detectedSeverity === 'needs_review' ? 'Uncertain Pattern (Needs Review)' : title,
      confidence_score: riskResult.confidenceScore,
      summary: detectedSeverity === 'needs_review' ? (textDetails?.reasoning || explanation.summary) : explanation.summary,
      ai_explanation: explanation.why_suspicious || explanation.aiExplanation,
      explanation,
      triggered_detectors: riskResult.triggered_detectors,
      recommended_action: finalRecommendedAction,
      detected_patterns: detectedPatterns,
      suspicious_phrases: suspiciousPhrases,
      scam_category: scamCategory,
      severity: detectedSeverity,
      evidence: riskResult.evidence,
      evidence_breakdown: riskResult.evidenceBreakdown,
      detector_results: evidenceCollection.detectorResults,
      detectors_evaluated: evidenceCollection.detectorResults.map((d) => d.detector_name),
      signals,
      recommended_actions: explanation.recommended_actions,
      safe_factors: explanation.safe_factors,
      technical_evidence: {
        language_detected: normalized.detectedLanguage,
        extracted_urls: normalized.extractedUrls,
        extracted_contacts: normalized.extractedPhoneNumbers,
        safe_factors: explanation.safe_factors,
        indicators_found: evidenceCollection.indicators,
      },
      created_at: new Date().toISOString(),
    };

    if (targetHash) {
      this.duplicateCache.set(targetHash, finalResult);
      if (this.redisClient && this.redisClient.status === 'ready') {
        this.redisClient.set(`pinit:dedup:${targetHash}`, JSON.stringify(finalResult), 'EX', 600).catch(() => {});
      }
    }

    if (input.type === 'URL') {
      metricsCollector.recordUrlAnalysis(Date.now() - startTime, false);
    }

    return finalResult;
  }
}

export const detectionPipeline = new DetectionPipeline();
