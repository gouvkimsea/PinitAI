import { describe, it, expect, beforeAll } from 'vitest';
import {
  scamIntelligenceService,
  SUPPORTED_SCAM_CATEGORIES,
  ScamCategory,
} from '../src/modules/intelligence';
import { scamPatternDetector } from '../src/pipeline/detectors/patternDetector';

describe('Structured Scam Intelligence Database & Comparison Service', () => {
  beforeAll(async () => {
    await scamIntelligenceService.initialize();
    await scamIntelligenceService.seedCatalog(true);
  });

  describe('1. Category Coverage (All 10 Required Categories)', () => {
    it('supports all 10 required scam categories', () => {
      const requiredCategories: ScamCategory[] = [
        'phishing',
        'fake_investment',
        'fake_job',
        'romance_scam',
        'payment_scam',
        'account_takeover',
        'impersonation',
        'lottery_scam',
        'cryptocurrency_scam',
        'tech_support_scam',
      ];

      for (const cat of requiredCategories) {
        expect(SUPPORTED_SCAM_CATEGORIES).toContain(cat);
      }
    });

    it('detects Phishing pattern', async () => {
      const text = 'Urgent security update: Click here to verify your account identity before suspension.';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toContain('phishing');
      expect(res.highest_severity).toBe('high');
    });

    it('detects Fake Investment pattern', async () => {
      const text = 'Join our VIP investment tier! Guaranteed daily profit and 200% returns guaranteed!';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toContain('fake_investment');
      expect(res.highest_severity).toBe('critical');
      expect(res.scam_score).toBeGreaterThanOrEqual(40);
    });

    it('detects Fake Job / Task scam pattern', async () => {
      const text = 'Exciting part-time job offer: Earn $500 daily just to like tiktok videos to earn income!';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toContain('fake_job');
      expect(res.highest_severity).toBe('high');
    });

    it('detects Romance scam pattern', async () => {
      const text = 'Hi sorry wrong number, you seem kind, let\'s chat on WhatsApp and invest with my uncle.';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toContain('romance_scam');
      expect(res.highest_severity).toBe('high');
    });

    it('detects Payment scam pattern', async () => {
      const text = 'Pay via Apple gift card immediately or pay via steam gift card to avoid tax penalties.';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toContain('payment_scam');
      expect(res.highest_severity).toBe('critical');
    });

    it('detects Account Takeover pattern', async () => {
      const text = 'System alert: Send me the 6-digit verification code you just received on your mobile phone.';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toContain('account_takeover');
      expect(res.highest_severity).toBe('critical');
    });

    it('detects Impersonation pattern', async () => {
      const text = 'Notice from ABA Bank: Unauthorized transaction detected and your account suspended immediately.';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toContain('impersonation');
      expect(res.highest_severity).toBe('critical');
    });

    it('detects Lottery scam pattern', async () => {
      const text = 'Congratulations you have won $5000 in lucky draw! Pay shipping fee to claim your prize.';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toContain('lottery_scam');
      expect(res.highest_severity).toBe('high');
    });

    it('detects Cryptocurrency scam pattern', async () => {
      const text = 'Official giveaway: Send 1 BTC and get double your btc back within 10 minutes!';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toContain('cryptocurrency_scam');
      expect(res.highest_severity).toBe('critical');
    });

    it('detects Tech-Support scam pattern', async () => {
      const text = 'Windows Defender Alert: Microsoft certified technician notice, call toll-free 1-800-555-0199 now!';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toContain('tech_support_scam');
      expect(res.highest_severity).toBe('critical');
    });

    it('detects Khmer language scam patterns', async () => {
      const text = 'សូមអបអរសាទរ អ្នកបានឈ្នះរង្វាន់ ប្រាក់ចំណេញធានា ១០០%';
      const res = await scamIntelligenceService.matchContent(text);

      expect(res.matched).toBe(true);
      expect(res.matched_patterns.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('2. Stored Record Schema Compliance', () => {
    it('stores all 8 required fields: Pattern, Category, Severity, Description, Source, CreatedAt, UpdatedAt, Status', async () => {
      const list = await scamIntelligenceService.getPatterns({ limit: 5 });
      expect(list.patterns.length).toBeGreaterThan(0);

      const record = list.patterns[0];
      expect(record).toHaveProperty('pattern');
      expect(record).toHaveProperty('category');
      expect(record).toHaveProperty('severity');
      expect(record).toHaveProperty('description');
      expect(record).toHaveProperty('source');
      expect(record).toHaveProperty('createdAt');
      expect(record).toHaveProperty('updatedAt');
      expect(record).toHaveProperty('status');

      expect(typeof record.pattern).toBe('string');
      expect(typeof record.category).toBe('string');
      expect(['low', 'medium', 'high', 'critical']).toContain(record.severity);
      expect(typeof record.description).toBe('string');
      expect(typeof record.source).toBe('string');
      expect(record.createdAt).toBeDefined();
      expect(record.updatedAt).toBeDefined();
      expect(['active', 'inactive', 'pending_review', 'deprecated']).toContain(record.status);
    });
  });

  describe('3. Dynamic Updates Without Changing Application Code', () => {
    const dynamicToken = `dynamic_test_token_${Date.now()}`;
    let createdId = '';

    it('creates a new pattern dynamically and immediately detects it in memory cache', async () => {
      const newPattern = await scamIntelligenceService.createPattern({
        pattern: `\\b${dynamicToken}\\b`,
        category: 'phishing',
        severity: 'critical',
        description: 'Dynamically injected test threat signature',
        source: 'automated_test_suite',
        status: 'active',
      });

      expect(newPattern.id).toBeDefined();
      createdId = newPattern.id;

      // Match content immediately without restarting backend
      const res = await scamIntelligenceService.matchContent(`Attention: check this payload with ${dynamicToken} enclosed.`);
      expect(res.matched).toBe(true);
      expect(res.matched_patterns.some((p) => p.id === createdId)).toBe(true);
      expect(res.highest_severity).toBe('critical');
    });

    it('updates pattern properties dynamically and hot-reloads cache', async () => {
      const updated = await scamIntelligenceService.updatePattern(createdId, {
        severity: 'low',
        description: 'Downgraded threat pattern severity',
      });

      expect(updated).not.toBeNull();
      expect(updated?.severity).toBe('low');

      const res = await scamIntelligenceService.matchContent(`Contains ${dynamicToken} here.`);
      expect(res.matched).toBe(true);
      const match = res.matched_patterns.find((p) => p.id === createdId);
      expect(match?.severity).toBe('low');
    });

    it('deletes pattern dynamically and immediately removes from detection', async () => {
      const deleted = await scamIntelligenceService.deletePattern(createdId);
      expect(deleted).toBe(true);

      const res = await scamIntelligenceService.matchContent(`Contains ${dynamicToken} here.`);
      expect(res.matched_patterns.some((p) => p.id === createdId)).toBe(false);
    });
  });

  describe('4. Content Comparison Service & Filtering', () => {
    it('returns structured comparison result for safe content', async () => {
      const safeText = 'Hey Sarah, are we still meeting for lunch tomorrow at 12:30? Let me know!';
      const res = await scamIntelligenceService.matchContent(safeText);

      expect(res.matched).toBe(false);
      expect(res.matched_patterns).toHaveLength(0);
      expect(res.categories_detected).toHaveLength(0);
      expect(res.highest_severity).toBe('safe');
      expect(res.scam_score).toBe(0);
      expect(res.execution_time_ms).toBeGreaterThanOrEqual(0);
    });

    it('supports category filtering in comparison options', async () => {
      const text = 'Urgent security update: verify your account. Also send 1 btc to double your crypto.';
      // Filter only for cryptocurrency_scam
      const res = await scamIntelligenceService.matchContent(text, {
        categories: ['cryptocurrency_scam'],
      });

      expect(res.matched).toBe(true);
      expect(res.categories_detected).toEqual(['cryptocurrency_scam']);
      expect(res.categories_detected).not.toContain('phishing');
    });

    it('supports minSeverity filtering in comparison options', async () => {
      const text = 'Your mailbox is full re-authenticate to prevent suspension.'; // medium severity
      const res = await scamIntelligenceService.matchContent(text, {
        minSeverity: 'critical',
      });

      // Medium pattern should be filtered out by minSeverity: critical
      expect(res.matched).toBe(false);
    });
  });

  describe('5. Pipeline Integration (ScamPatternDetector)', () => {
    it('integrates with ScamPatternDetector in detection pipeline', async () => {
      const result = await scamPatternDetector.detect(
        {
          raw: 'Urgent notice: ABA Bank account suspended! Send 6-digit OTP code to verify immediately.',
          type: 'TEXT',
          normalizedText: 'urgent notice aba bank account suspended send 6-digit otp code to verify immediately',
        },
        { scanId: 'test-scan-intel-01', inputType: 'TEXT', startTime: Date.now() }
      );

      expect(result).not.toBeNull();
      expect(result?.detector_name).toBe('scam_pattern_detector');
      expect(result?.severity).toBe('critical');
      expect(result?.score).toBeGreaterThanOrEqual(45);
      expect(result?.evidence.details?.matched_count).toBeGreaterThanOrEqual(1);
    });
  });
});
