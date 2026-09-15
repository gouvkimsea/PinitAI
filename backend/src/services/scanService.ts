import fs from 'fs';
import path from 'path';
import prisma from '../database/client';
import { calculateFileHashes } from '../scanners/hash/hashScanner';
import { analyzeMagicBytes } from '../scanners/file/magicBytes';
import { analyzeFileStatically } from '../scanners/file/staticAnalyzer';
import { scanWithClamAV } from '../scanners/antivirus/clamavScanner';
import { analyzeUrl } from '../scanners/url/urlScanner';
import { threatIntel } from '../scanners/threatIntel/threatIntelProvider';
import { aggregateResults } from '../scanners/aggregator/resultAggregator';
import { sanitizeFilename, secureDeleteFile } from '../utils/helpers';
import { logger } from '../utils/logger';
import { explanationEngine } from '../modules/ai/explanationEngine';
import { detectionPipeline } from '../pipeline/orchestrator';
import { DetectionItem } from '../types';

export class ScanService {
  /**
   * Processes a file scan across all detection engines and saves results to DB.
   */
  async processFileScan(scanId: string, tempFilePath: string, originalName: string, mimeType: string): Promise<void> {
    const startTime = Date.now();
    logger.info('Starting file security analysis', { scanId, originalName });

    try {
      // 1. Mark scan as processing
      const updateRes = await prisma.scan.updateMany({
        where: { id: scanId },
        data: { status: 'PROCESSING' },
      });
      if (updateRes.count === 0) {
        logger.warn('Scan was cancelled or deleted before processing', { scanId });
        return;
      }

      const stats = await fs.promises.stat(tempFilePath);
      const sizeBytes = stats.size;
      const sanitizedName = sanitizeFilename(originalName);
      const extension = path.extname(sanitizedName).replace('.', '').toLowerCase();

      // 2. Compute Hashes
      const hashes = await calculateFileHashes(tempFilePath);

      // 3. Inspect Magic Bytes
      const magicResult = await analyzeMagicBytes(tempFilePath, extension, mimeType);

      // 4. Query Threat Intelligence by Hash
      const hashIntel = await threatIntel.checkHash(hashes.sha256);

      // 5. Static Pattern & Heuristics
      const staticResult = await analyzeFileStatically(tempFilePath, sanitizedName, sizeBytes);

      // 6. Antivirus Scan (ClamAV / Simulated fallback)
      const avResult = await scanWithClamAV(tempFilePath);

      // Collect all detections
      const allDetections: DetectionItem[] = [
        ...magicResult.detections,
        ...staticResult.detections,
        ...avResult.detections,
      ];

      if (hashIntel && hashIntel.detections) {
        allDetections.push(...hashIntel.detections);
      }

      const enginesEvaluated = ['HashCalculation', 'MagicBytesEngine', 'StaticAnalyzer', avResult.engine];
      if (hashIntel) enginesEvaluated.push(hashIntel.provider);

      // 7. Aggregate Threat Assessment
      const aggregated = aggregateResults({
        targetType: 'FILE',
        detections: allDetections,
        enginesEvaluated,
        safeFactorsObserved: [],
        context: {
          isMimeMatch: !magicResult.isMismatch,
          fileName: sanitizedName,
        },
      });

      const durationMs = Date.now() - startTime;

      // Check existence before starting transaction
      const stillExists = await prisma.scan.findUnique({ where: { id: scanId } });
      if (!stillExists) {
        logger.warn('Scan record was removed before results could be saved', { scanId });
        return;
      }

      // 8. Transactional Database Write
      await prisma.$transaction(async (tx) => {
        // Create File Record
        const fileRecord = await tx.fileRecord.create({
          data: {
            scanId,
            originalName,
            sanitizedName,
            mimeType,
            detectedMimeType: magicResult.detectedMimeType,
            sizeBytes,
            extension,
          },
        });

        // Create File Hashes
        await tx.fileHash.create({
          data: {
            fileId: fileRecord.id,
            sha256: hashes.sha256,
            sha1: hashes.sha1,
            md5: hashes.md5,
          },
        });

        // Create Detections (batch insert — one round-trip instead of N)
        if (allDetections.length > 0) {
          await tx.detection.createMany({
            data: allDetections.map((det) => ({
              scanId,
              engine: det.engine,
              category: det.category,
              severity: det.severity,
              ruleId: det.ruleId,
              title: det.title,
              description: det.description,
              details: det.details ? JSON.stringify(det.details) : null,
            })),
          });
        }

        // Enrich with AI Explanation Layer
        const fileExp = explanationEngine.generateExplanation({
          targetType: 'FILE',
          threatCategory: allDetections[0]?.category || 'FILE_INSPECTION',
          riskScore: aggregated.riskScore,
          indicators: allDetections.map((d) => d.title),
        });

        const mergedSafeFactors = Array.from(new Set([...aggregated.safeFactors, ...fileExp.safeFactors]));
        const mergedRecommendations = Array.from(new Set([...aggregated.recommendations, ...fileExp.recommendedActions]));

        // Create Scan Result Summary
        await tx.scanResult.create({
          data: {
            scanId,
            summary: fileExp.summary || aggregated.summary,
            totalEngines: aggregated.totalEngines,
            maliciousEngines: aggregated.maliciousEngines,
            suspiciousEngines: aggregated.suspiciousEngines,
            cleanEngines: aggregated.cleanEngines,
            safeFactors: JSON.stringify(mergedSafeFactors),
            recommendations: JSON.stringify(mergedRecommendations),
          },
        });

        // Create Analysis Evidence
        await tx.analysisEvidence.create({
          data: {
            scanId,
            summary: fileExp.summary || aggregated.summary,
            indicators: JSON.stringify(allDetections.map((d) => d.title)),
            evidenceBreakdown: JSON.stringify({}),
            technicalEvidence: JSON.stringify({
              why_suspicious: fileExp.aiExplanation || fileExp.summary || aggregated.summary,
              detected_mime: magicResult.detectedMimeType,
              clamav_result: avResult.detections.length > 0 ? 'infected' : 'clean',
              sha256: hashes.sha256,
            }),
            uncertaintyNotes: null,
            groundedScore: aggregated.threatConfidence === 'HIGH' ? 95 : 80,
          },
        });

        // Update Scan Record
        await tx.scan.update({
          where: { id: scanId },
          data: {
            status: 'COMPLETED',
            riskLevel: aggregated.threatLevel,
            riskScore: aggregated.riskScore,
            threatConfidence: aggregated.threatConfidence,
            scanDurationMs: durationMs,
            completedAt: new Date(),
          },
        });
      });

      logger.info('File scan completed successfully', {
        scanId,
        threatLevel: aggregated.threatLevel,
        riskScore: aggregated.riskScore,
        detectionsCount: allDetections.length,
        durationMs,
      });
    } catch (err) {
      const isRecordNotFound =
        (err as any)?.code === 'P2025' ||
        (err as any)?.code === 'P2003' ||
        (err as Error).message?.includes('No record was found') ||
        (err as Error).message?.includes('Foreign key constraint violated');
      if (isRecordNotFound) {
        logger.warn('File scan record was removed before results could be saved', { scanId });
      } else {
        logger.trackFileProcessingFailure({
          scanId,
          fileName: originalName,
          error: (err as Error).message,
          stage: 'multi_engine_analysis',
        });
        logger.error('File scan failed', { scanId, error: (err as Error).message, stack: (err as Error).stack });
        try {
          const stillExists = await prisma.scan.findUnique({ where: { id: scanId } });
          if (stillExists) {
            await prisma.scan.update({
              where: { id: scanId },
              data: {
                status: 'FAILED',
                errorMessage: (err as Error).message,
                completedAt: new Date(),
              },
            });
          }
        } catch {
          // scan was likely deleted concurrently
        }
      }
    } finally {
      // 9. Mandatory Security Requirement: Securely delete temporary file
      await secureDeleteFile(tempFilePath);
    }
  }

  /**
   * Processes a URL scan and saves results to DB.
   */
  async processUrlScan(scanId: string, url: string): Promise<void> {
    const startTime = Date.now();
    logger.info('Starting URL security analysis', { scanId, url });

    try {
      const updateRes = await prisma.scan.updateMany({
        where: { id: scanId },
        data: { status: 'PROCESSING' },
      });
      if (updateRes.count === 0) {
        logger.warn('Scan was cancelled or deleted before processing', { scanId });
        return;
      }

      // 1. Analyze URL structure, SSRF, keywords, and redirect chain
      const urlAnalysis = await analyzeUrl(url);

      // 2. Query Domain Threat Intelligence
      const domainIntel = await threatIntel.checkDomain(urlAnalysis.metadata.domain);

      const allDetections: DetectionItem[] = [...urlAnalysis.detections];
      if (domainIntel && domainIntel.detections) {
        allDetections.push(...domainIntel.detections);
      }

      const enginesEvaluated = ['SSRFGuard', 'URLValidator', 'URLPhishingEngine'];
      if (domainIntel) enginesEvaluated.push(domainIntel.provider);

      // 3. Aggregate Results
      const aggregated = aggregateResults({
        targetType: 'URL',
        detections: allDetections,
        enginesEvaluated,
        context: {
          isHttps: urlAnalysis.metadata.isHttps,
          url,
        },
      });

      const durationMs = Date.now() - startTime;

      // Check existence before starting transaction
      const stillExists = await prisma.scan.findUnique({ where: { id: scanId } });
      if (!stillExists) {
        logger.warn('Scan record was removed before results could be saved', { scanId });
        return;
      }

      // 4. Transactional Database Write
      await prisma.$transaction(async (tx) => {
        await tx.urlScan.create({
          data: {
            scanId,
            url: urlAnalysis.metadata.url,
            normalizedUrl: urlAnalysis.metadata.normalizedUrl,
            domain: urlAnalysis.metadata.domain,
            ipAddress: urlAnalysis.metadata.ipAddress,
            isHttps: urlAnalysis.metadata.isHttps,
            hasRedirects: urlAnalysis.metadata.hasRedirects,
            redirectCount: urlAnalysis.metadata.redirectCount,
          },
        });

        // Create Detections (batch insert — one round-trip instead of N)
        if (allDetections.length > 0) {
          await tx.detection.createMany({
            data: allDetections.map((det) => ({
              scanId,
              engine: det.engine,
              category: det.category,
              severity: det.severity,
              ruleId: det.ruleId,
              title: det.title,
              description: det.description,
              details: det.details ? JSON.stringify(det.details) : null,
            })),
          });
        }

        // Enrich with AI Explanation Layer
        const urlExp = explanationEngine.generateExplanation({
          targetType: 'URL',
          threatCategory: allDetections[0]?.category || 'URL_INSPECTION',
          riskScore: aggregated.riskScore,
          indicators: allDetections.map((d) => d.title),
        });

        const mergedSafeFactors = Array.from(new Set([...aggregated.safeFactors, ...urlExp.safeFactors]));
        const mergedRecommendations = Array.from(new Set([...aggregated.recommendations, ...urlExp.recommendedActions]));

        await tx.scanResult.create({
          data: {
            scanId,
            summary: urlExp.summary || aggregated.summary,
            totalEngines: aggregated.totalEngines,
            maliciousEngines: aggregated.maliciousEngines,
            suspiciousEngines: aggregated.suspiciousEngines,
            cleanEngines: aggregated.cleanEngines,
            safeFactors: JSON.stringify(mergedSafeFactors),
            recommendations: JSON.stringify(mergedRecommendations),
          },
        });

        // Create Analysis Evidence
        await tx.analysisEvidence.create({
          data: {
            scanId,
            summary: urlExp.summary || aggregated.summary,
            indicators: JSON.stringify(allDetections.map((d) => d.title)),
            evidenceBreakdown: JSON.stringify({}),
            technicalEvidence: JSON.stringify({
              why_suspicious: urlExp.aiExplanation || urlExp.summary || aggregated.summary,
              normalized_url: urlAnalysis.metadata.normalizedUrl,
              domain: urlAnalysis.metadata.domain,
              ip: urlAnalysis.metadata.ipAddress,
              https: urlAnalysis.metadata.isHttps,
            }),
            uncertaintyNotes: null,
            groundedScore: aggregated.threatConfidence === 'HIGH' ? 95 : 80,
          },
        });

        await tx.scan.update({
          where: { id: scanId },
          data: {
            status: 'COMPLETED',
            riskLevel: aggregated.threatLevel,
            riskScore: aggregated.riskScore,
            threatConfidence: aggregated.threatConfidence,
            scanDurationMs: durationMs,
            completedAt: new Date(),
          },
        });
      });

      logger.info('URL scan completed successfully', {
        scanId,
        threatLevel: aggregated.threatLevel,
        riskScore: aggregated.riskScore,
        durationMs,
      });
    } catch (err) {
      const isRecordNotFound =
        (err as any)?.code === 'P2025' ||
        (err as any)?.code === 'P2003' ||
        (err as Error).message?.includes('No record was found') ||
        (err as Error).message?.includes('Foreign key constraint violated');
      if (isRecordNotFound) {
        logger.warn('URL scan record was removed before results could be saved', { scanId });
      } else {
        logger.error('URL scan failed', { scanId, error: (err as Error).message });
        try {
          const stillExists = await prisma.scan.findUnique({ where: { id: scanId } });
          if (stillExists) {
            await prisma.scan.update({
              where: { id: scanId },
              data: {
                status: 'FAILED',
                errorMessage: (err as Error).message,
                completedAt: new Date(),
              },
            });
          }
        } catch {
          // scan was likely deleted concurrently
        }
      }
    }
  }

  /**
   * Processes a text scan / linguistic analysis asynchronously and saves results to DB.
   */
  async processTextScan(scanId: string, content: string, userId?: string | null): Promise<void> {
    const startTime = Date.now();
    logger.info('Starting asynchronous text security analysis', { scanId, preview: content.slice(0, 60) });

    try {
      await prisma.scan.updateMany({
        where: { id: scanId },
        data: { status: 'PROCESSING' },
      });

      await detectionPipeline.execute({
        scanId,
        type: 'TEXT',
        rawContent: content,
        userId: userId || null,
      });

      logger.info('Asynchronous text analysis completed successfully', {
        scanId,
        durationMs: Date.now() - startTime,
      });
    } catch (err) {
      logger.error('Asynchronous text scan failed', { scanId, error: (err as Error).message });
      try {
        await prisma.scan.updateMany({
          where: { id: scanId },
          data: {
            status: 'FAILED',
            errorMessage: (err as Error).message,
            completedAt: new Date(),
          },
        });
      } catch {
        // Record was likely removed
      }
    }
  }

  /**
   * Processes an AI explanation job asynchronously and saves results to DB.
   */
  async processAiExplanationJob(scanId: string, data: any, _userId?: string | null): Promise<void> {
    const startTime = Date.now();
    logger.info('Starting asynchronous AI explanation job', { scanId });

    try {
      await prisma.scan.updateMany({
        where: { id: scanId },
        data: { status: 'PROCESSING' },
      });

      const explanation = await explanationEngine.generateStructuredExplanation({
        targetType: data.target_type || 'TEXT',
        threatCategory: data.threat_category || 'SUSPICIOUS_CONTENT',
        riskScore: data.risk_score || 50,
        indicators: data.indicators || [],
        rawContentSnippet: data.content || data.scan_id || 'AI Analysis Request',
        language: data.language || 'en',
      });

      await prisma.scan.updateMany({
        where: { id: scanId },
        data: {
          status: 'COMPLETED',
          riskScore: data.risk_score || 50,
          completedAt: new Date(),
          scanDurationMs: Date.now() - startTime,
        },
      });

      await prisma.scanResult.upsert({
        where: { scanId },
        create: {
          scanId,
          summary: explanation.summary,
          safeFactors: JSON.stringify(explanation.safe_factors),
          recommendations: JSON.stringify(explanation.recommended_actions),
        },
        update: {
          summary: explanation.summary,
          safeFactors: JSON.stringify(explanation.safe_factors),
          recommendations: JSON.stringify(explanation.recommended_actions),
        },
      });

      await prisma.analysisEvidence.upsert({
        where: { scanId },
        create: {
          scanId,
          summary: explanation.summary,
          indicators: JSON.stringify(data.indicators || []),
          evidenceBreakdown: JSON.stringify({}),
          technicalEvidence: JSON.stringify({
            why_suspicious: explanation.why_suspicious,
            scam_type: explanation.scam_type,
            actionable_advice: explanation.actionable_advice,
            uncertainty_notes: explanation.uncertainty_notes,
          }),
          uncertaintyNotes: JSON.stringify(explanation.uncertainty_notes),
          groundedScore: explanation.grounded_in_evidence ? 100 : 70,
        },
        update: {
          summary: explanation.summary,
          indicators: JSON.stringify(data.indicators || []),
          evidenceBreakdown: JSON.stringify({}),
          technicalEvidence: JSON.stringify({
            why_suspicious: explanation.why_suspicious,
            scam_type: explanation.scam_type,
            actionable_advice: explanation.actionable_advice,
            uncertainty_notes: explanation.uncertainty_notes,
          }),
          uncertaintyNotes: JSON.stringify(explanation.uncertainty_notes),
          groundedScore: explanation.grounded_in_evidence ? 100 : 70,
        },
      });

      logger.info('Asynchronous AI explanation job completed successfully', {
        scanId,
        durationMs: Date.now() - startTime,
      });
    } catch (err) {
      logger.error('Asynchronous AI explanation job failed', { scanId, error: (err as Error).message });
      try {
        await prisma.scan.updateMany({
          where: { id: scanId },
          data: {
            status: 'FAILED',
            errorMessage: (err as Error).message,
            completedAt: new Date(),
          },
        });
      } catch {
        // Record was likely removed
      }
    }
  }
}

export const scanService = new ScanService();
