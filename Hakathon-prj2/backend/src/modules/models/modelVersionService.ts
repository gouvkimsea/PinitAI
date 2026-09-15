import prisma from '../../database/client';
import { logger } from '../../utils/logger';

export interface ModelVersionData {
  name: string;
  version: string;
  modelType: 'heuristic' | 'llm_explanation' | 'classifier' | 'antivirus' | 'regex';
  provider: 'Internal' | 'GoogleGemini' | 'ClamAV' | 'VirusTotal';
  isActive: boolean;
  capabilities: string[];
}

export const DEFAULT_PLATFORM_MODELS: ModelVersionData[] = [
  {
    name: 'gemini-grounded-explainer',
    version: '2.1.0',
    modelType: 'llm_explanation',
    provider: 'GoogleGemini',
    isActive: true,
    capabilities: ['TEXT', 'URL', 'FILE', 'QR'],
  },
  {
    name: 'text-linguistic-detector',
    version: '2.0.0',
    modelType: 'heuristic',
    provider: 'Internal',
    isActive: true,
    capabilities: ['TEXT'],
  },
  {
    name: 'khmer-scam-pattern-matcher',
    version: '1.5.0',
    modelType: 'regex',
    provider: 'Internal',
    isActive: true,
    capabilities: ['TEXT'],
  },
  {
    name: 'clamav-antivirus-engine',
    version: '1.4.2',
    modelType: 'antivirus',
    provider: 'ClamAV',
    isActive: true,
    capabilities: ['FILE'],
  },
  {
    name: 'url-impersonation-heuristics',
    version: '2.0.0',
    modelType: 'heuristic',
    provider: 'Internal',
    isActive: true,
    capabilities: ['URL', 'QR'],
  },
  {
    name: 'virustotal-reputation-engine',
    version: '3.0.0',
    modelType: 'classifier',
    provider: 'VirusTotal',
    isActive: true,
    capabilities: ['FILE', 'URL'],
  },
];

export class ModelVersionService {
  /**
   * Seeds or syncs default platform model versions on service startup.
   */
  async seedDefaultModelVersions(): Promise<number> {
    let synced = 0;
    for (const model of DEFAULT_PLATFORM_MODELS) {
      try {
        await prisma.modelVersion.upsert({
          where: {
            name_version: {
              name: model.name,
              version: model.version,
            },
          },
          update: {
            modelType: model.modelType,
            provider: model.provider,
            isActive: model.isActive,
            capabilities: JSON.stringify(model.capabilities),
          },
          create: {
            name: model.name,
            version: model.version,
            modelType: model.modelType,
            provider: model.provider,
            isActive: model.isActive,
            capabilities: JSON.stringify(model.capabilities),
          },
        });
        synced++;
      } catch (err) {
        logger.warn('Failed to upsert default model version', {
          model: model.name,
          error: (err as Error).message,
        });
      }
    }
    logger.info('Model version registry synced', { count: synced });
    return synced;
  }

  /**
   * List registered models with optional active filter.
   */
  async listModels(onlyActive = true) {
    return prisma.modelVersion.findMany({
      where: onlyActive ? { isActive: true } : {},
      orderBy: [{ provider: 'asc' }, { name: 'asc' }],
    });
  }

  /**
   * Look up specific model by name and optional version.
   */
  async getModel(name: string, version?: string) {
    if (version) {
      return prisma.modelVersion.findUnique({
        where: { name_version: { name, version } },
      });
    }
    return prisma.modelVersion.findFirst({
      where: { name, isActive: true },
      orderBy: { createdAt: 'desc' },
    });
  }
}

export const modelVersionService = new ModelVersionService();
