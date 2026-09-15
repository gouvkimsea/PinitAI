import { sanitizeFilename } from '../../utils/helpers';

export interface NormalizedFileResult {
  originalName: string;
  sanitizedName: string;
  extension: string;
  doubleExtension?: string;
  isDoubleExtension: boolean;
  mimeType: string;
}

export class FileNormalizer {
  private static readonly EXECUTABLE_EXTENSIONS = new Set([
    'exe', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jse', 'wsf', 'scr', 'pif', 'com', 'hta', 'cpl', 'jar'
  ]);

  private static readonly DOCUMENT_EXTENSIONS = new Set([
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv', 'png', 'jpg', 'jpeg'
  ]);

  /**
   * Normalizes file metadata and checks for deceptive extension tricks.
   */
  normalize(originalName: string, mimeType: string = 'application/octet-stream'): NormalizedFileResult {
    const sanitizedName = sanitizeFilename(originalName || 'unnamed_upload');
    const parts = sanitizedName.toLowerCase().split('.');

    let extension = '';
    let doubleExtension: string | undefined = undefined;
    let isDoubleExtension = false;

    if (parts.length > 1) {
      extension = parts[parts.length - 1];
    }

    if (parts.length > 2) {
      const secondToLast = parts[parts.length - 2];
      // Check for deceptive double extensions like receipt.pdf.exe
      if (FileNormalizer.DOCUMENT_EXTENSIONS.has(secondToLast) && FileNormalizer.EXECUTABLE_EXTENSIONS.has(extension)) {
        isDoubleExtension = true;
        doubleExtension = `${secondToLast}.${extension}`;
      }
    }

    return {
      originalName,
      sanitizedName,
      extension,
      doubleExtension,
      isDoubleExtension,
      mimeType: mimeType.toLowerCase().trim(),
    };
  }
}

export const fileNormalizer = new FileNormalizer();
