import { textNormalizer } from './textNormalizer';
import { urlNormalizer } from './urlNormalizer';
import { fileNormalizer } from './fileNormalizer';
import { InputType, NormalizedInput, PipelineInput } from '../types';

export * from './textNormalizer';
export * from './urlNormalizer';
export * from './fileNormalizer';

export class InputNormalizer {
  /**
   * Normalizes any polymorphic pipeline input into a standardized NormalizedInput
   */
  normalize(input: PipelineInput): NormalizedInput {
    const raw = input.rawContent || input.originalFileName || '';
    const type: InputType = input.type;

    let normalizedText: string | undefined = undefined;
    let deobfuscatedText: string | undefined = undefined;
    let normalizedUrl: string | undefined = undefined;
    let urlDomain: string | undefined = undefined;
    let sanitizedFileName: string | undefined = undefined;
    let fileExtension: string | undefined = undefined;
    let detectedLanguage: 'en' | 'km' | 'km-en' | 'unknown' | undefined = undefined;
    let extractedUrls: string[] = [];
    let extractedPhoneNumbers: string[] = [];

    if (type === 'TEXT') {
      const res = textNormalizer.normalize(raw);
      normalizedText = res.cleanedText;
      deobfuscatedText = res.deobfuscatedText;
      detectedLanguage = res.detectedLanguage;
      extractedUrls = res.extractedUrls;
      extractedPhoneNumbers = res.extractedPhoneNumbers;
    } else if (type === 'URL' || type === 'QR') {
      const res = urlNormalizer.normalize(raw);
      normalizedUrl = res.normalizedUrl;
      urlDomain = res.domain;
      extractedUrls = [res.normalizedUrl];
    } else if (type === 'FILE') {
      const res = fileNormalizer.normalize(input.originalFileName || raw, input.mimeType);
      sanitizedFileName = res.sanitizedName;
      fileExtension = res.extension;
    }

    return {
      type,
      raw,
      normalizedText,
      deobfuscatedText,
      normalizedUrl,
      urlDomain,
      sanitizedFileName,
      fileExtension,
      fileSizeBytes: input.metadata?.sizeBytes,
      fileMimeType: input.mimeType,
      detectedLanguage,
      extractedUrls,
      extractedPhoneNumbers,
    };
  }
}

export const inputNormalizer = new InputNormalizer();
