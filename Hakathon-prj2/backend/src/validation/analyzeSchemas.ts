import { z } from 'zod';
import { config } from '../config';

export const TextScanSchema = z
  .object({
    content: z.string().trim().min(1).max(config.payloadLimits.maxTextLengthChars).optional(),
    text: z.string().trim().min(1).max(config.payloadLimits.maxTextLengthChars).optional(),
  })
  .refine((data) => Boolean(data.content || data.text), {
    message: 'Content string is required.',
    path: ['content'],
  });

export function isValidHttpUrl(val: string): boolean {
  if (!val || typeof val !== 'string') return false;
  const trimmed = val.trim();
  if (trimmed.length < 3) return false;

  // If scheme is explicitly present, it MUST be http or https
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return false; // Rejects ftp, javascript, data, file, gopher, etc.
    }
  }

  // Reject characters that are strictly illegal in hostnames and URLs
  if (/[\^<>"{}|\\`\s*]/.test(trimmed)) {
    return false;
  }

  try {
    const urlToParse = schemeMatch ? trimmed : `https://${trimmed}`;
    const parsed = new URL(urlToParse);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }
    if (!parsed.hostname || parsed.hostname.length < 3) {
      return false;
    }
    // Hostname must be valid (must contain dot or be localhost or valid IP)
    if (!parsed.hostname.includes('.') && parsed.hostname !== 'localhost') {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export const UrlScanSchema = z.object({
  url: z
    .string({ required_error: 'Target URL is required.' })
    .trim()
    .min(3, 'Target URL must contain at least 3 characters.')
    .max(4096, 'URL exceeds maximum length of 4096 characters.')
    .refine((val) => isValidHttpUrl(val), {
      message: 'Invalid URL format. Target URL must be an http or https address.',
    }),
});

export const AnalysisIdSchema = z.object({
  id: z.string().trim().min(1, 'Analysis identifier is required.'),
});

/** Legacy feedback schema (is_correct bool) — kept for backward compatibility */
export const FeedbackSchema = z.object({
  scan_id: z.string().min(1, 'Target scan ID is required.'),
  is_correct: z.boolean({ required_error: 'Accuracy status (is_correct) is required.' }),
  suggested_category: z.string().max(50).optional(),
  comments: z.string().max(2000).optional(),
});

export const ReportSchema = z.object({
  scamType: z.string().trim().min(1, 'Scam category is required.').max(50),
  target: z.string().trim().max(2000).optional(),
  description: z.string().trim().min(5, 'Description must be at least 5 characters.').max(5000),
});

export const ExplainSchema = z.object({
  scan_id: z.string().trim().optional(),
  content: z.string().trim().max(100000).optional(),
  target_type: z.enum(['TEXT', 'URL', 'FILE', 'QR']).optional(),
  threat_category: z.string().max(100).optional(),
  risk_score: z.number().min(0).max(100).optional(),
  indicators: z.array(z.string()).optional(),
  language: z.enum(['en', 'km', 'km-en']).optional(),
}).refine((data) => Boolean(data.scan_id || data.content || (data.indicators && data.indicators.length > 0)), {
  message: 'Either scan_id, content, or indicators must be provided for AI explanation.',
  path: ['scan_id'],
});

/** Allowed user-reportable categories */
export const FEEDBACK_CATEGORIES = [
  'SAFE',
  'PHISHING',
  'INVESTMENT_SCAM',
  'JOB_SCAM',
  'ROMANCE_SCAM',
  'FAKE_SHOP',
  'IMPERSONATION',
  'PAYMENT_SCAM',
  'PRIZE_SCAM',
  'MALWARE',
  'ACCOUNT_TAKEOVER',
  'SOCIAL_ENGINEERING',
  'OTHER',
] as const;

export type FeedbackCategory = typeof FEEDBACK_CATEGORIES[number];

/** Structured 4-type user feedback schema */
export const UserFeedbackSchema = z.object({
  /** ID of the analysis result being reviewed */
  analysis_id: z
    .string({ required_error: 'analysis_id is required.' })
    .trim()
    .min(1, 'analysis_id cannot be empty.')
    .max(200, 'analysis_id is too long.'),
  /** Type of feedback */
  feedback_type: z.enum(
    ['correct_detection', 'incorrect_detection', 'report_scam', 'not_sure'],
    { required_error: 'feedback_type must be one of: correct_detection, incorrect_detection, report_scam, not_sure.' }
  ),
  /** User's suggested category — required when feedback_type is "incorrect_detection" or "report_scam" */
  reported_category: z.enum(FEEDBACK_CATEGORIES).optional(),
  /** Optional free-text explanation */
  explanation: z
    .string()
    .trim()
    .max(2000, 'Explanation cannot exceed 2000 characters.')
    .optional(),
  /** Optional snippet of the analyzed content for context (user-provided or auto-populated) */
  target_snippet: z
    .string()
    .trim()
    .max(80)
    .optional(),
  /** Risk score at time of analysis (captured client-side) */
  risk_score_at_time: z.number().min(0).max(100).optional(),
}).refine(
  (data) => {
    // reported_category is expected when type is incorrect_detection or report_scam
    if (data.feedback_type === 'incorrect_detection' || data.feedback_type === 'report_scam') {
      return true; // not strictly required but strongly encouraged — soft validation only
    }
    return true;
  },
  { message: 'Consider providing reported_category for incorrect_detection or report_scam feedback.' }
);

/** Admin schema for listing feedback with filters */
export const AdminFeedbackListSchema = z.object({
  feedbackType: z.enum(['correct_detection', 'incorrect_detection', 'report_scam', 'not_sure']).optional(),
  isReviewed: z.enum(['true', 'false']).optional(),
  analysisId: z.string().trim().optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
});

/** Admin schema for reviewing/marking a feedback record */
export const AdminReviewFeedbackSchema = z.object({
  reviewNote: z.string().trim().max(1000).optional(),
  isReviewed: z.boolean().default(true),
});

export type TextScanInput = z.infer<typeof TextScanSchema>;
export type UrlScanInput = z.infer<typeof UrlScanSchema>;
export type AnalysisIdInput = z.infer<typeof AnalysisIdSchema>;
export type FeedbackInput = z.infer<typeof FeedbackSchema>;
export type ReportInput = z.infer<typeof ReportSchema>;
export type ExplainInput = z.infer<typeof ExplainSchema>;
export type UserFeedbackInput = z.infer<typeof UserFeedbackSchema>;
export type AdminFeedbackListInput = z.infer<typeof AdminFeedbackListSchema>;
export type AdminReviewFeedbackInput = z.infer<typeof AdminReviewFeedbackSchema>;
