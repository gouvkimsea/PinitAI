import { describe, it, expect } from 'vitest';
import request from 'supertest';
import { createApp } from '../src/app';
import { messageScamEngine } from '../src/modules/message/messageScamEngine';
import { messageNormalizer } from '../src/modules/message/messageNormalizer';
import { entityExtractor } from '../src/modules/message/entityExtractor';

describe('Dedicated Message Scam Detection Engine', () => {
  const app = createApp();
  // =========================================================================
  // 1. All 28 Behavioral Patterns Detection
  // =========================================================================
  describe('1. All 28 Behavioral Patterns Coverage', () => {
    it('Pattern 1: Urgency', () => {
      const res = messageScamEngine.analyze('Act now! This limited time offer expires today, immediate response required!');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'URGENCY')).toBe(true);
      expect(res.evidence.some((e) => e.signal === 'Creates artificial urgency')).toBe(true);
    });

    it('Pattern 2: Threats', () => {
      const res = messageScamEngine.analyze('Police warrant issued! Pay immediately or face arrest and court summons.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'THREATS')).toBe(true);
      expect(res.evidence.some((e) => e.signal === 'Threatens police arrest or legal action')).toBe(true);
    });

    it('Pattern 3: Account suspension claims', () => {
      const res = messageScamEngine.analyze('Security alert: Your account has been suspended due to unauthorized login detected.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'ACCOUNT_SUSPENSION')).toBe(true);
      expect(res.evidence.some((e) => e.signal === 'Claims account has been locked or suspended')).toBe(true);
    });

    it('Pattern 4: Fake rewards', () => {
      const res = messageScamEngine.analyze('Congratulations! You won $50,000 cash prize in our lucky draw winner lottery!');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'FAKE_REWARDS')).toBe(true);
      expect(res.scamCategories).toContain('PRIZE_SCAM');
    });

    it('Pattern 5: Fake jobs', () => {
      const res = messageScamEngine.analyze('Part-time job hiring: Earn $300 daily by liking youtube videos from home.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'FAKE_JOBS')).toBe(true);
      expect(res.scamCategories).toContain('JOB_SCAM');
    });

    it('Pattern 6: Fake investments', () => {
      const res = messageScamEngine.analyze('Guaranteed 100% returns daily! Deposit USDT to double your crypto risk-free.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'FAKE_INVESTMENTS')).toBe(true);
      expect(res.scamCategories).toContain('INVESTMENT_SCAM');
    });

    it('Pattern 7: Fake loans', () => {
      const res = messageScamEngine.analyze('Emergency loan approved! Instant loan with zero credit check and no collateral loan.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'FAKE_LOANS')).toBe(true);
      expect(res.scamCategories).toContain('LOAN_SCAM');
    });

    it('Pattern 8: Fake deliveries', () => {
      const res = messageScamEngine.analyze('Postal notice: Package delivery failed due to unpaid customs fee. Update your delivery address.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'FAKE_DELIVERIES')).toBe(true);
      expect(res.scamCategories).toContain('DELIVERY_SCAM');
    });

    it('Pattern 9: Fake government communication', () => {
      const res = messageScamEngine.analyze('General Department of Taxation alert: Tax penalty notice for unfiled foreign assets.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'FAKE_GOVERNMENT_COMMUNICATION')).toBe(true);
    });

    it('Pattern 10: Fake bank communication', () => {
      const res = messageScamEngine.analyze('Notice from ABA Bank customer service regarding unauthorized transaction on your card.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'FAKE_BANK_COMMUNICATION')).toBe(true);
      expect(res.extractedEntities.brands).toContain('ABA Bank');
    });

    it('Pattern 11: Fake customer support', () => {
      const res = messageScamEngine.analyze('Hello, this is Telegram Support team. A security agent needs to verify your identity.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'FAKE_CUSTOMER_SUPPORT')).toBe(true);
    });

    it('Pattern 12: Romance manipulation', () => {
      const res = messageScamEngine.analyze('Sorry wrong number, but you seem like a kind person. Let us chat privately honey.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'ROMANCE_MANIPULATION')).toBe(true);
      expect(res.scamCategories).toContain('ROMANCE_SCAM');
    });

    it('Pattern 13: Payment requests', () => {
      const res = messageScamEngine.analyze('Please send money immediately. Wire transfer $500 to my account today.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'PAYMENT_REQUESTS')).toBe(true);
    });

    it('Pattern 14: Advance-fee requests', () => {
      const res = messageScamEngine.analyze('To claim your funds, you must pay upfront clearance fee of $50 before release.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'ADVANCE_FEE_REQUESTS')).toBe(true);
    });

    it('Pattern 15: OTP requests', () => {
      const res = messageScamEngine.analyze('Verification required: Please enter otp code sent to your phone or send otp now.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'OTP_REQUESTS')).toBe(true);
      expect(res.extractedEntities.requestedCredentials).toContain('OTP / One-Time Password');
    });

    it('Pattern 16: Password requests', () => {
      const res = messageScamEngine.analyze('Account validation: Provide your login password to prevent permanent termination.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'PASSWORD_REQUESTS')).toBe(true);
      expect(res.extractedEntities.requestedCredentials).toContain('Account Password');
    });

    it('Pattern 17: PIN requests', () => {
      const res = messageScamEngine.analyze('ATM card upgrade: Please enter your 4-digit pin to verify your pin code.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'PIN_REQUESTS')).toBe(true);
      expect(res.extractedEntities.requestedCredentials).toContain('PIN Code');
    });

    it('Pattern 18: Banking credential requests', () => {
      const res = messageScamEngine.analyze('Card verification: Please enter card number and cvv security code on the back.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'BANKING_CREDENTIAL_REQUESTS')).toBe(true);
      expect(res.extractedEntities.requestedCredentials).toContain('Banking / Card Details');
    });

    it('Pattern 19: Identity-document requests', () => {
      const res = messageScamEngine.analyze('Compliance check: Send photo of id card and a selfie with id to verify your profile.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'IDENTITY_DOCUMENT_REQUESTS')).toBe(true);
      expect(res.extractedEntities.requestedCredentials).toContain('Government Identity Document');
    });

    it('Pattern 20: Remote-access requests', () => {
      const res = messageScamEngine.analyze('To resolve your technical glitch, please install anydesk and allow screen sharing.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'REMOTE_ACCESS_REQUESTS')).toBe(true);
      expect(res.extractedEntities.requestedCredentials).toContain('Remote Access Software');
    });

    it('Pattern 21: Suspicious downloads', () => {
      const res = messageScamEngine.analyze('Security patch: Please download apk to install update file and secure your phone.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'SUSPICIOUS_DOWNLOADS')).toBe(true);
      expect(res.extractedEntities.requestedCredentials).toContain('Suspicious Software / APK Download');
    });

    it('Pattern 22: Suspicious links', () => {
      const res = messageScamEngine.analyze('Account alert: Click here to verify your identity before midnight.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'SUSPICIOUS_LINKS')).toBe(true);
    });

    it('Pattern 23: Impersonation', () => {
      const res = messageScamEngine.analyze('Official notice on behalf of Apple Support regarding unauthorized iCloud sign-in.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'IMPERSONATION')).toBe(true);
    });

    it('Pattern 24: Financial manipulation', () => {
      const res = messageScamEngine.analyze('I accidentally sent you $500 via mobile banking. Please refund the excess money.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'FINANCIAL_MANIPULATION')).toBe(true);
    });

    it('Pattern 25: Fear-based manipulation', () => {
      const res = messageScamEngine.analyze('If you refuse to comply, all funds will be confiscated and your name blacklisted.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'FEAR_BASED_MANIPULATION')).toBe(true);
    });

    it('Pattern 26: Authority impersonation', () => {
      const res = messageScamEngine.analyze('This is Detective Miller from the Cyber Crime Unit investigating financial fraud.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'AUTHORITY_IMPERSONATION')).toBe(true);
    });

    it('Pattern 27: Excessive urgency', () => {
      const res = messageScamEngine.analyze('You have 5 minutes remaining! In the next 10 minutes all benefits will be deleted!');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'EXCESSIVE_URGENCY')).toBe(true);
    });

    it('Pattern 28: Requests to move conversation to another platform', () => {
      const res = messageScamEngine.analyze('I cannot chat here. Add my whatsapp wa.me/123456 or join the telegram channel @crypto_vip.');
      expect(res.behavioralPatterns.some((p) => p.patternType === 'REQUESTS_TO_MOVE_PLATFORM')).toBe(true);
    });
  });

  // =========================================================================
  // 2. Multilingual & Khmer Support
  // =========================================================================
  describe('2. Multilingual & Mixed Script Detection', () => {
    it('should detect pure Khmer scam message with bank impersonation and credential harvesting', () => {
      const pureKmMsg = 'ធនាគារអេស៊ីលីដា៖ គណនីត្រូវបានផ្អាក! សូមផ្ញើលេខកូដសម្ងាត់ជាបន្ទាន់ដើម្បីដោះសោ។';
      const res = messageScamEngine.analyze(pureKmMsg);

      expect(res.language).toBe('km');
      expect(res.riskScore).toBeGreaterThanOrEqual(75);
      expect(res.riskLevel).toMatch(/CONFIRMED_MALICIOUS|HIGHLY_SUSPICIOUS/);
      expect(res.evidence.some((e) => e.signal === 'Requests an OTP' || e.signal === 'Requests a Banking PIN Code' || e.signal === 'Claims account has been locked or suspended')).toBe(true);
    });

    it('should detect mixed Khmer and English scam message with loan lure', () => {
      const mixedMsg = 'ដំណឹងពិសេស! Fast instant loan អនុម័តប្រាក់កម្ចីរហូតដល់ $10,000 គ្មានទ្រព្យបញ្ចាំ! Click here to apply.';
      const res = messageScamEngine.analyze(mixedMsg);

      expect(res.language).toBe('km-en');
      expect(res.scamCategories).toContain('LOAN_SCAM');
      expect(res.riskScore).toBeGreaterThanOrEqual(60);
    });

    it('should detect Khmer prize scam message', () => {
      const kmPrize = 'សូមអបអរសាទរ! អ្នកបានឈ្នះរង្វាន់ទឹកប្រាក់ $5,000 ពីការចាប់ឆ្នោត!';
      const res = messageScamEngine.analyze(kmPrize);

      expect(res.language).toBe('km');
      expect(res.scamCategories).toContain('PRIZE_SCAM');
    });
  });

  // =========================================================================
  // 3. Evasion, Misspellings, Obfuscation & Internet Slang
  // =========================================================================
  describe('3. Obfuscation & Evasion Normalization', () => {
    it('should deobfuscate zero-width invisible spaces between credential keywords', () => {
      // "p\u200Ba\u200Bs\u200Bs\u200Bw\u200Bo\u200Br\u200Bd"
      const evasiveMsg = 'Urgent: Enter your p\u200Ba\u200Bs\u200Bs\u200Bw\u200Bo\u200Br\u200Bd and enter otp code now!';
      const res = messageScamEngine.analyze(evasiveMsg);

      expect(res.behavioralPatterns.some((p) => p.patternType === 'PASSWORD_REQUESTS' || p.patternType === 'OTP_REQUESTS')).toBe(true);
      expect(res.extractedEntities.requestedCredentials.length).toBeGreaterThan(0);
    });

    it('should deobfuscate Cyrillic homoglyphs used in brand and payment names', () => {
      // Cyrillic 'а' (\u0430) in "PаyPаl" and "bаnk"
      const homoglyphMsg = 'Security team: Your P\u0430yP\u0430l b\u0430nk account has been suspended! Enter otp immediately.';
      const res = messageScamEngine.analyze(homoglyphMsg);

      expect(res.riskScore).toBeGreaterThanOrEqual(75);
      expect(res.behavioralPatterns.some((p) => p.patternType === 'ACCOUNT_SUSPENSION')).toBe(true);
    });

    it('should reduce excessive character repetitions (e.g. urgentttt, hurryyy)', () => {
      const repeatedMsg = 'Act now hurryyy! This is urgentttt, enter your passworddd to claim your prizeee!';
      const res = messageScamEngine.analyze(repeatedMsg);

      expect(res.behavioralPatterns.some((p) => p.patternType === 'URGENCY')).toBe(true);
    });

    it('should normalize deliberate single-letter delimiter splits (e.g. u.r.g.e.n.t, w-i-r-e)', () => {
      const splitMsg = 'Final notice: u.r.g.e.n.t wire transfer required within 24 hours!';
      const res = messageScamEngine.analyze(splitMsg);

      expect(res.behavioralPatterns.some((p) => p.patternType === 'URGENCY')).toBe(true);
      expect(res.behavioralPatterns.some((p) => p.patternType === 'PAYMENT_REQUESTS')).toBe(true);
    });

    it('should defang obfuscated URLs (e.g. hxxps[://]secure[.]bank[.]com)', () => {
      const defangedMsg = 'Click hxxps[://]verify[.]aba-security[.]com/login to secure your account.';
      const norm = messageNormalizer.normalize(defangedMsg);

      expect(norm.hasObfuscation).toBe(true);
      expect(norm.defanged).toContain('https://verify.aba-security.com/login');
    });

    it('should handle common internet slang and misspellings', () => {
      const slangMsg = 'Hey kindly hmu on tele @crypto_whale for ez money and passive income guaranteed returns!';
      const res = messageScamEngine.analyze(slangMsg);

      expect(res.behavioralPatterns.some((p) => p.patternType === 'FAKE_INVESTMENTS')).toBe(true);
      expect(res.extractedEntities.socialHandles.some((h) => h.handle === '@crypto_whale')).toBe(true);
    });
  });

  // =========================================================================
  // 4. Entity Extraction
  // =========================================================================
  describe('4. Comprehensive Entity Extraction', () => {
    it('should extract shortened URLs, phone numbers, emails, and crypto addresses', () => {
      const complexMsg = 'Contact admin@cryptopool.org or +855 12 345 678. Send 500 USDT to TRON address TJYkKqB1c8g9P2w4m5X7z8V9b0N1m2L3k4 or check bit.ly/promo50';
      const entities = entityExtractor.extract(complexMsg, complexMsg.toLowerCase());

      expect(entities.emailAddresses).toContain('admin@cryptopool.org');
      expect(entities.phoneNumbers.length).toBeGreaterThan(0);
      expect(entities.cryptoAddresses.some((c) => c.type === 'USDT_TRC20')).toBe(true);
      expect(entities.urls.some((u) => u.includes('bit.ly'))).toBe(true);
    });

    it('should extract ABA Bank account numbers and payment handles', () => {
      const paymentMsg = 'Please pay to ABA: 000 123 456 or send via CashApp $fastcash50.';
      const entities = entityExtractor.extract(paymentMsg, paymentMsg.toLowerCase());

      expect(entities.bankAccounts.some((b) => b.bank === 'ABA Bank' && b.accountNumber === '000123456')).toBe(true);
      expect(entities.paymentHandles.some((p) => p.provider === 'CashApp' && p.identifier === '$fastcash50')).toBe(true);
    });
  });

  // =========================================================================
  // 5. Anti-Unilateral Principle & Calibrated Uncertainty
  // =========================================================================
  describe('5. Anti-Unilateral Principle & Calibrated Uncertainty', () => {
    it('should return UNKNOWN_INSUFFICIENT_EVIDENCE for an isolated weak urgency keyword in benign text', () => {
      const ambiguous = 'Could you please reply urgently regarding the project review meeting?';
      const res = messageScamEngine.analyze(ambiguous);

      expect(res.riskLevel).toBe('UNKNOWN_INSUFFICIENT_EVIDENCE');
      expect(res.riskScore).toBeLessThanOrEqual(25);
      expect(res.confidence).toBeLessThan(50);
      expect(res.explanation).toContain("I don't have enough evidence to determine whether this is a scam");
    });

    it('should return SAFE for completely clean conversational text with score 0', () => {
      const benign = 'Hi Sarah, are we still meeting for lunch tomorrow at 12:30 PM? Let me know!';
      const res = messageScamEngine.analyze(benign);

      expect(res.riskLevel).toBe('SAFE');
      expect(res.riskScore).toBe(0);
      expect(res.confidence).toBeGreaterThanOrEqual(85);
      expect(res.behavioralPatterns).toEqual([]);
      expect(res.intent.primaryIntent).toBe('BENIGN_CONVERSATION');
    });

    it('should apply correlation boost for multiple corroborating threat patterns', () => {
      const compoundScam = 'Notice from ABA Bank: Account suspended due to fraud! Enter your password and OTP immediately within 10 minutes at bit.ly/aba-verify';
      const res = messageScamEngine.analyze(compoundScam);

      expect(res.riskLevel).toBe('CONFIRMED_MALICIOUS');
      expect(res.riskScore).toBeGreaterThanOrEqual(85);
      expect(res.confidence).toBeGreaterThanOrEqual(80);
      expect(res.evidence.length).toBeGreaterThanOrEqual(3);
    });
  });

  // =========================================================================
  // 6. HTTP API Integration (POST /api/analyze/message)
  // =========================================================================
  describe('6. HTTP API Integration (POST /api/analyze/message)', () => {
    it('POST /api/analyze/message should return exact structured JSON format', async () => {
      const payload = {
        content: 'URGENT: Your bank account is locked! Send OTP code to verify identity or face legal action: bit.ly/verify-now',
      };

      const res = await request(app)
        .post('/api/analyze/message')
        .send(payload);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      // Verify all required user-specified contract fields
      expect(res.body.riskLevel).toBeDefined();
      expect(typeof res.body.riskScore).toBe('number');
      expect(typeof res.body.confidence).toBe('number');
      expect(Array.isArray(res.body.scamCategories)).toBe(true);
      expect(Array.isArray(res.body.indicators)).toBe(true);
      expect(typeof res.body.extractedEntities).toBe('object');
      expect(typeof res.body.recommendedAction).toBe('string');
      expect(typeof res.body.explanation).toBe('string');
      expect(Array.isArray(res.body.evidence)).toBe(true);

      // Verify evidence items contain grounded details
      expect(res.body.evidence.length).toBeGreaterThan(0);
      expect(res.body.evidence[0]).toHaveProperty('signal');
      expect(res.body.evidence[0]).toHaveProperty('category');
      expect(res.body.evidence[0]).toHaveProperty('severity');
      expect(res.body.evidence[0]).toHaveProperty('details');
    });

    it('POST /api/analyze/message should reject empty request body with 400', async () => {
      const res = await request(app)
        .post('/api/analyze/message')
        .send({});

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });
});
