import { describe, it, expect } from 'vitest';
import { textDetector } from '../src/modules/text/textDetector';

describe('Enhanced Text & Message Scam Detection System', () => {
  describe('1. Individual Detection for All 12 Scam Patterns', () => {
    it('Pattern 1: Urgency', () => {
      const msg = 'Final notice: You must act immediately within 24 hours or your service expires today!';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Urgency');
      expect(res.suspicious_phrases.some((p) => /immediately|within 24 hours|final notice/i.test(p))).toBe(true);
    });

    it('Pattern 2: Threats', () => {
      const msg = 'Police warrant issued against you. Pay your penalty or face immediate arrest and court lawsuit.';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Threats');
      expect(res.suspicious_phrases.some((p) => /arrest|lawsuit|police/i.test(p))).toBe(true);
      expect(res.severity).toBe('critical');
    });

    it('Pattern 3: Requests for money', () => {
      const msg = 'Please wire transfer $500 to my account or send funds directly today.';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Requests for money');
      expect(res.suspicious_phrases.some((p) => /wire transfer|send funds/i.test(p))).toBe(true);
    });

    it('Pattern 4: Requests for passwords or OTPs', () => {
      const msg = 'Security team notification: Please provide your bank credentials and enter otp code now.';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Requests for passwords or OTPs');
      expect(res.suspicious_phrases.some((p) => /credentials|otp/i.test(p))).toBe(true);
      expect(res.severity).toBe('critical');
    });

    it('Pattern 5: Fake prizes', () => {
      const msg = 'Congratulations! You won $50,000 cash prize in our lucky draw winner promotion!';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Fake prizes');
      expect(res.suspicious_phrases.some((p) => /congratulations|cash prize|lucky draw/i.test(p))).toBe(true);
      expect(res.scam_category).toBe('PRIZE_SCAM');
    });

    it('Pattern 6: Fake jobs', () => {
      const msg = 'Hiring part-time job now! Earn $500 per day by rating products and liking videos.';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Fake jobs');
      expect(res.suspicious_phrases.some((p) => /earn \$500 per day|part-time job/i.test(p))).toBe(true);
      expect(res.scam_category).toBe('JOB_SCAM');
    });

    it('Pattern 7: Investment scams', () => {
      const msg = 'Guaranteed returns of 200% daily! Double your crypto now with our automated bitcoin doubling platform.';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Investment scams');
      expect(res.suspicious_phrases.some((p) => /guaranteed returns|crypto investment|double your crypto/i.test(p))).toBe(true);
      expect(res.scam_category).toBe('INVESTMENT_SCAM');
    });

    it('Pattern 8: Romance scams', () => {
      const msg = 'Sorry wrong number, but you seem nice. Let us chat on whatsapp privately.';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Romance scams');
      expect(res.suspicious_phrases.some((p) => /sorry wrong number|whatsapp/i.test(p))).toBe(true);
      expect(res.scam_category).toBe('ROMANCE_SCAM');
    });

    it('Pattern 9: Account takeover attempts', () => {
      const msg = 'Security alert: Your account has been suspended due to unauthorized login detected. Reactivate your account now.';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Account takeover attempts');
      expect(res.suspicious_phrases.some((p) => /account has been suspended|unauthorized login detected/i.test(p))).toBe(true);
      expect(res.severity).toBe('critical');
    });

    it('Pattern 10: Impersonation', () => {
      const msg = 'Official notice from ABA Bank Customer Service regarding your account security.';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Impersonation');
      expect(res.suspicious_phrases.some((p) => /aba bank/i.test(p))).toBe(true);
    });

    it('Pattern 11: Suspicious payment instructions', () => {
      const msg = 'Urgent: Please buy Apple gift cards and send usdt to wallet address 0x93F... to settle this bill.';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Suspicious payment instructions');
      expect(res.suspicious_phrases.some((p) => /buy apple gift cards|send usdt to wallet/i.test(p))).toBe(true);
    });

    it('Pattern 12: Requests to click suspicious links', () => {
      const msg = 'Important verification needed: Please click here to verify your details immediately.';
      const res = textDetector.analyzeStructured(msg);

      expect(res.detected_patterns).toContain('Requests to click suspicious links');
      expect(res.suspicious_phrases.some((p) => /click here/i.test(p))).toBe(true);
    });
  });

  describe('2. Exact Suspicious Phrases & Evidence Extraction', () => {
    it('should extract exact phrases from compound scam message', () => {
      const scamMsg = 'URGENT: Your account has been suspended! Send your password to unlock or click the link below.';
      const res = textDetector.analyzeStructured(scamMsg);

      expect(res.suspicious_phrases.length).toBeGreaterThanOrEqual(3);
      expect(res.evidence.suspicious_phrases).toEqual(res.suspicious_phrases);
      expect(res.evidence.indicators.length).toBeGreaterThanOrEqual(3);
      expect(res.evidence.summary).toBeDefined();
      expect(res.evidence.reasoning).toBeDefined();
    });
  });

  describe('3. Support for Uncertain Results ("needs_review")', () => {
    it('should return needs_review for ambiguous or borderline message with isolated weak signal', () => {
      // Message has an isolated weak urgency word in an otherwise benign inquiry
      const ambiguousMsg = 'Hey, can you please reply within 24 hours regarding the project notes?';
      const res = textDetector.analyzeStructured(ambiguousMsg);

      expect(res.severity).toBe('needs_review');
      expect(res.scam_category).toBe('needs_review');
      expect(res.recommended_action).toContain('NEEDS REVIEW');
      expect(res.confidence).toBeLessThanOrEqual(60);
    });

    it('should return SAFE for completely clean conversational text', () => {
      const cleanMsg = 'Hello, let us meet for lunch tomorrow at 12 PM at the office cafeteria.';
      const res = textDetector.analyzeStructured(cleanMsg);

      expect(res.severity).toBe('safe');
      expect(res.scam_category).toBe('SAFE');
      expect(res.score).toBe(0);
      expect(res.detected_patterns).toEqual([]);
      expect(res.suspicious_phrases).toEqual([]);
    });
  });

  describe('4. Structured Results Format Completeness', () => {
    it('should return all required contract fields', () => {
      const msg = 'Congratulations! You won $10,000 cash. Wire transfer $50 clearance fee to claim prize immediately!';
      const res = textDetector.analyzeStructured(msg);

      expect(res).toHaveProperty('detected_patterns');
      expect(Array.isArray(res.detected_patterns)).toBe(true);
      expect(res.detected_patterns.length).toBeGreaterThan(0);

      expect(res).toHaveProperty('suspicious_phrases');
      expect(Array.isArray(res.suspicious_phrases)).toBe(true);
      expect(res.suspicious_phrases.length).toBeGreaterThan(0);

      expect(res).toHaveProperty('scam_category');
      expect(typeof res.scam_category).toBe('string');
      expect(res.scam_category).not.toBe('scam'); // Must not be generic "scam"

      expect(res).toHaveProperty('severity');
      expect(['safe', 'low', 'medium', 'high', 'critical', 'needs_review']).toContain(res.severity);

      expect(res).toHaveProperty('confidence');
      expect(typeof res.confidence).toBe('number');
      expect(res.confidence).toBeGreaterThanOrEqual(0);
      expect(res.confidence).toBeLessThanOrEqual(100);

      expect(res).toHaveProperty('evidence');
      expect(res.evidence).toHaveProperty('summary');
      expect(res.evidence).toHaveProperty('indicators');
      expect(res.evidence).toHaveProperty('suspicious_phrases');
      expect(res.evidence).toHaveProperty('category_scores');
      expect(res.evidence).toHaveProperty('reasoning');

      expect(res).toHaveProperty('recommended_action');
      expect(typeof res.recommended_action).toBe('string');
      expect(res.recommended_action.length).toBeGreaterThan(10);
    });
  });

  describe('5. Khmer Language Scam Detection', () => {
    it('should detect Khmer prize scam with exact phrases', () => {
      const khmerMsg = 'សូមអបអរសាទរ! អ្នកបានឈ្នះរង្វាន់ $5,000 ផ្ញើប្រាក់ដើម្បីទទួលរង្វាន់ជាបន្ទាន់!';
      const res = textDetector.analyzeStructured(khmerMsg);

      expect(res.language).toBe('km');
      expect(res.detected_patterns.length).toBeGreaterThanOrEqual(2);
      expect(res.suspicious_phrases.length).toBeGreaterThanOrEqual(2);
      expect(res.scam_category).toBe('PRIZE_SCAM');
    });
  });
});
