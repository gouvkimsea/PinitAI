import { EvaluationSample, SampleLanguage, NuanceTag } from './types';
import { SCAM_SAMPLES } from './scamSamples';
import { LEGITIMATE_SAMPLES } from './legitimateSamples';

export * from './types';
export * from './scamSamples';
export * from './legitimateSamples';

/**
 * Returns the entire balanced systematic evaluation dataset.
 */
export function getBenchmarkDataset(): EvaluationSample[] {
  return [...SCAM_SAMPLES, ...LEGITIMATE_SAMPLES];
}

/**
 * Filters evaluation samples by target language.
 */
export function getSamplesByLanguage(language: SampleLanguage): EvaluationSample[] {
  return getBenchmarkDataset().filter((s) => s.language === language);
}

/**
 * Filters evaluation samples by category.
 */
export function getSamplesByCategory(category: string): EvaluationSample[] {
  return getBenchmarkDataset().filter((s) => s.category.toLowerCase() === category.toLowerCase());
}

/**
 * Filters evaluation samples by nuance tag (e.g. 'slang_shorthand', 'shortened_url').
 */
export function getSamplesByTag(tag: NuanceTag): EvaluationSample[] {
  return getBenchmarkDataset().filter((s) => s.nuanceTags.includes(tag));
}

/**
 * Validates dataset balance and integrity.
 */
export function validateDatasetIntegrity(): {
  isValid: boolean;
  total: number;
  scamCount: number;
  legitimateCount: number;
  scamCategoriesCovered: string[];
  legitimateCategoriesCovered: string[];
  languagesCovered: string[];
  errors: string[];
} {
  const dataset = getBenchmarkDataset();
  const errors: string[] = [];

  const scamSamples = dataset.filter((s) => s.expectedLabel === 'SCAM');
  const legitimateSamples = dataset.filter((s) => s.expectedLabel === 'LEGITIMATE');

  const scamCategories = Array.from(new Set(scamSamples.map((s) => s.category)));
  const legitimateCategories = Array.from(new Set(legitimateSamples.map((s) => s.category)));
  const languages = Array.from(new Set(dataset.map((s) => s.language)));

  // Verify all IDs are unique
  const idSet = new Set<string>();
  for (const sample of dataset) {
    if (idSet.has(sample.id)) {
      errors.push(`Duplicate sample ID detected: ${sample.id}`);
    }
    idSet.add(sample.id);
  }

  // Verify at least 15 scam categories and 10 legitimate categories
  if (scamCategories.length < 16) {
    errors.push(`Scam category coverage under 16: found ${scamCategories.length}`);
  }
  if (legitimateCategories.length < 10) {
    errors.push(`Legitimate category coverage under 10: found ${legitimateCategories.length}`);
  }

  // Verify balance ratio is between 40% and 60%
  const scamRatio = scamSamples.length / dataset.length;
  if (scamRatio < 0.4 || scamRatio > 0.6) {
    errors.push(`Dataset is not balanced: scam ratio is ${(scamRatio * 100).toFixed(1)}%`);
  }

  return {
    isValid: errors.length === 0,
    total: dataset.length,
    scamCount: scamSamples.length,
    legitimateCount: legitimateSamples.length,
    scamCategoriesCovered: scamCategories,
    legitimateCategoriesCovered: legitimateCategories,
    languagesCovered: languages,
    errors,
  };
}
