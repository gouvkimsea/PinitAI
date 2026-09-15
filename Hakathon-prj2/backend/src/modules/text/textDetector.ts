import { DetectionItem } from '../../types';

export type TextSeverity = 'safe' | 'low' | 'medium' | 'high' | 'critical' | 'needs_review';

export interface StructuredTextScamResult {
  detected_patterns: string[];
  suspicious_phrases: string[];
  scam_category: string;
  severity: TextSeverity;
  confidence: number;
  evidence: {
    summary: string;
    indicators: string[];
    suspicious_phrases: string[];
    category_scores: Record<string, number>;
    reasoning: string;
  };
  recommended_action: string;
  score: number;
  language: 'en' | 'km' | 'km-en' | 'unknown';
}

export interface TextDetectionResult {
  language: 'en' | 'km' | 'km-en' | 'unknown';
  threatCategory: string;
  categoryScores: Record<string, number>;
  signals: DetectionItem[];
  detectedIndicators: string[];
  suspiciousPhrases: string[];
  detectedPatterns: string[];
  structured: StructuredTextScamResult;
}

interface PatternRule {
  id: string;
  patternName: string;
  category: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  weight: number;
  regex: RegExp;
}

const RULES: PatternRule[] = [
  // 1. Urgency Pressure
  {
    id: 'TXT-URG-01',
    patternName: 'Urgency',
    category: 'urgency',
    title: 'Manufactured Urgency & Time Pressure',
    description: 'Demands immediate action or imposes artificial time limits to bypass critical thinking.',
    severity: 'high',
    weight: 25,
    regex: /\b(immediately|urgent|urgently|act now|hurry|within 24 hours|within \d+ (minutes|hours)|final notice|expires? (today|soon|in \d+)|before it expires|last warning|limited time only|immediate response required)\b/i,
  },
  {
    id: 'TXT-URG-KM-01',
    patternName: 'Urgency',
    category: 'urgency',
    title: 'Manufactured Urgency (Khmer)',
    description: 'Demands urgent action in Khmer script.',
    severity: 'high',
    weight: 25,
    regex: /(បន្ទាន់|ជាបន្ទាន់|ក្នុងរយៈពេល \d+|ដំណឹងចុងក្រោយ|ផុតកំណត់ថ្ងៃនេះ|ព្រមានចុងក្រោយ)/u,
  },

  // 2. Intimidation & Threats
  {
    id: 'TXT-THREAT-01',
    patternName: 'Threats',
    category: 'coercion',
    title: 'Intimidation, Arrest & Legal Threats',
    description: 'Uses fear of police arrest, lawsuits, court warrants, or severe penalties to compel compliance.',
    severity: 'critical',
    weight: 35,
    regex: /\b(arrest|police warrant|lawsuit|legal action|court summons|warrant for your arrest|block account permanently|face jail time|penalties apply|criminal charges)\b/i,
  },
  {
    id: 'TXT-THREAT-KM-01',
    patternName: 'Threats',
    category: 'coercion',
    title: 'Intimidation & Legal Threats (Khmer)',
    description: 'Khmer text threatening arrest, court prosecution, or permanent forfeiture.',
    severity: 'critical',
    weight: 35,
    regex: /(ជាប់គុក|ប៉ូលីស|តុលាការ|ដីកាចាប់ខ្លួន|ចាត់វិធានការច្បាប់|បិទគណនីជាអចិន្ត្រៃយ៍|ពិន័យធ្ងន់ធ្ងរ)/u,
  },

  // 3. Requests for Money
  {
    id: 'TXT-MONEY-01',
    patternName: 'Requests for money',
    category: 'payment',
    title: 'Direct Solicitation of Funds / Money Requests',
    description: 'Requests sending money, wire transfers, funds transfer, or cash deposits.',
    severity: 'high',
    weight: 30,
    regex: /\b(send\s+(?:money|funds|cash|\$?\d+|\d+\s*(?:\$|usd|usdt|btc|eth|dollars?|riel))|transfer\s+(?:money|funds|cash|\$?\d+|\d+\s*(?:\$|usd|usdt|btc|eth|dollars?|riel))|wire\s+(?:transfer|money|funds)|deposit\s+(?:money|funds|\$?\d+)|pay\s+(?:upfront|fee|deposit)|borrow\s+money|cash\s+advance|remit\s+funds)\b/i,
  },
  {
    id: 'TXT-MONEY-KM-01',
    patternName: 'Requests for money',
    category: 'payment',
    title: 'Direct Solicitation of Funds (Khmer)',
    description: 'Requests transferring money or funds in Khmer.',
    severity: 'high',
    weight: 30,
    regex: /(ផ្ទេរប្រាក់|ផ្ញើប្រាក់|បង់ប្រាក់|កក់ប្រាក់|ដាក់ប្រាក់|ផ្ញើលុយ|ផ្ទេរលុយ)/u,
  },

  // 4. Requests for Passwords or OTPs
  {
    id: 'TXT-OTP-01',
    patternName: 'Requests for passwords or OTPs',
    category: 'credentials',
    title: 'Credential / OTP / PIN Solicitation',
    description: 'Directly asks for authentication credentials, password, PIN code, or one-time verification tokens.',
    severity: 'critical',
    weight: 40,
    regex: /\b(password|otp|one-time password|pin code|security code|credentials|bank credentials|enter (otp|pin|passcode)|verify your credentials|send your password|provide your pin)\b/i,
  },
  {
    id: 'TXT-OTP-KM-01',
    patternName: 'Requests for passwords or OTPs',
    category: 'credentials',
    title: 'Credential / OTP Request (Khmer)',
    description: 'Khmer prompt requesting secret codes, OTP, password, or PIN.',
    severity: 'critical',
    weight: 40,
    regex: /(ពាក្យសម្ងាត់|លេខកូដសម្ងាត់|កូដ otp|លេខសម្ងាត់|ផ្ញើលេខកូដ|ផ្ញើពាក្យសម្ងាត់)/u,
  },

  // 5. Fake Prizes & Lotteries
  {
    id: 'TXT-PRZ-01',
    patternName: 'Fake prizes',
    category: 'reward',
    title: 'Unsolicited Prize / Lottery Claim Scheme',
    description: 'Claims unexpected monetary rewards, free luxury gifts, or lottery jackpots.',
    severity: 'high',
    weight: 30,
    regex: /\b(congratulations|you have won|you won \$|claim your (prize|reward|giftcard|\$\d+)|lottery (prize|account|ticket|winner)|lucky draw winner|selected as the winner|free gift card|cash prize|receive your prize)\b/i,
  },
  {
    id: 'TXT-PRZ-KM-01',
    patternName: 'Fake prizes',
    category: 'reward',
    title: 'Fake Prize / Lucky Winner (Khmer)',
    description: 'Khmer text promising lottery prizes or free winnings.',
    severity: 'high',
    weight: 30,
    regex: /(សូមអបអរសាទរ|អ្នកបានឈ្នះរង្វាន់|អ្នកមានសំណាង|ទទួលរង្វាន់|ឈ្នះប្រាក់|ចាប់ឆ្នោតឈ្នះ|កាដូឥតគិតថ្លៃ)/u,
  },

  // 6. Fake Jobs & Task Schemes
  {
    id: 'TXT-JOB-01',
    patternName: 'Fake jobs',
    category: 'employment',
    title: 'Deceptive Remote Task / Fake Job Offer',
    description: 'Advertises unrealistic daily earnings for simple online tasks, liking videos, or VIP review jobs.',
    severity: 'high',
    weight: 30,
    regex: /\b(earn \$[0-9]+ (per day|daily)|part-time (job|work)|work from home|telegram job|daily payout|like (youtube|tiktok) videos|daily salary \$|complete simple tasks to earn)\b/i,
  },
  {
    id: 'TXT-JOB-KM-01',
    patternName: 'Fake jobs',
    category: 'employment',
    title: 'Fake Job / Task Scheme (Khmer)',
    description: 'Khmer text offering unrealistic daily pay for online tasks.',
    severity: 'high',
    weight: 30,
    regex: /(ការងារក្រៅម៉ោង|រកចំណូលប្រចាំថ្ងៃ|ធ្វើការងារតាមទូរស័ព្ទ|មើលវីដេអូបានលុយ|ប្រាក់បៀវត្សរ៍ប្រចាំថ្ងៃ|ចុច like បានលុយ)/u,
  },

  // 7. Investment Scams & Crypto Fraud
  {
    id: 'TXT-INV-01',
    patternName: 'Investment scams',
    category: 'financial',
    title: 'Unrealistic Investment / Crypto Duplication Scheme',
    description: 'Promises guaranteed returns, crypto doubling, high-yield investment programs, or risk-free trading.',
    severity: 'critical',
    weight: 35,
    regex: /\b(guaranteed (100%|daily|returns)|crypto investment|double your (crypto|btc|eth|money)|forex trading pool|passive income guarantee|deposit usdt to double|cloud mining contract)\b/i,
  },
  {
    id: 'TXT-INV-KM-01',
    patternName: 'Investment scams',
    category: 'financial',
    title: 'Crypto / Investment Scheme (Khmer)',
    description: 'Khmer text claiming guaranteed investment profits or crypto doubling.',
    severity: 'critical',
    weight: 35,
    regex: /(ការវិនិយោគចំណេញ|ចំណេញ១០០%|គ្រីបតូទ្វេដង|ដាក់ប្រាក់ចំណេញ|ប្រាក់ចំណេញខ្ពស់ធានា|ទ្វេដងលុយ)/u,
  },

  // 8. Romance Scams & Pig Butchering
  {
    id: 'TXT-ROM-01',
    patternName: 'Romance scams',
    category: 'romance',
    title: 'Romance / Social Engineering "Pig Butchering" Pattern',
    description: 'Builds false intimacy, wrong number pretext, or redirects conversation to private messengers for financial extraction.',
    severity: 'high',
    weight: 30,
    regex: /\b(sorry wrong number|let's chat on (whatsapp|telegram)|are you the golf coach|my assistant gave me your number|dear sweetheart|meet on whatsapp|let us chat privately)\b/i,
  },
  {
    id: 'TXT-ROM-KM-01',
    patternName: 'Romance scams',
    category: 'romance',
    title: 'Romance / Pretext Scam (Khmer)',
    description: 'Pretexting wrong numbers or private chat redirects in Khmer.',
    severity: 'high',
    weight: 30,
    regex: /(សុំទោសច្រឡំលេខ|ជជែកគ្នាតាម telegram|ជជែកគ្នាតាម whatsapp|ស្គាល់គ្នាបានទេ)/u,
  },

  // 9. Account Takeover Attempts
  {
    id: 'TXT-ATO-01',
    patternName: 'Account takeover attempts',
    category: 'account_takeover',
    title: 'Account Takeover / Suspension Alert Lure',
    description: 'Claims account has been locked, suspended, or flagged for unauthorized access to lure credentials.',
    severity: 'critical',
    weight: 35,
    regex: /\b(account (has been|is) (suspended|locked|frozen|compromised)|unauthorized login detected|security lockout|reactivate your account|sign in to prevent closure|unlock your account)\b/i,
  },
  {
    id: 'TXT-ATO-KM-01',
    patternName: 'Account takeover attempts',
    category: 'account_takeover',
    title: 'Account Takeover Alert (Khmer)',
    description: 'Khmer alerts claiming account has been suspended or compromised.',
    severity: 'critical',
    weight: 35,
    regex: /(គណនីត្រូវបានផ្អាក|គណនីត្រូវបានចាក់សោ|រកឃើញការលួចចូល|ចុចដើម្បីដោះសោ|ផ្អាកជាបណ្តោះអាសន្ន)/u,
  },

  // 10. Impersonation (Banks, Authorities, Executive)
  {
    id: 'TXT-IMP-01',
    patternName: 'Impersonation',
    category: 'impersonation',
    title: 'Brand, Bank, or Authority Impersonation',
    description: 'Impersonates trusted institutions like ABA Bank, Wing, ACLEDA, PayPal, Chase, or Government departments.',
    severity: 'high',
    weight: 30,
    regex: /\b(aba bank|acleda|wing bank|canadia bank|paypal|binance|apple support|chase bank|internal revenue|tax department|police department|customer service agent)\b/i,
  },
  {
    id: 'TXT-IMP-KM-01',
    patternName: 'Impersonation',
    category: 'impersonation',
    title: 'Bank / Authority Impersonation (Khmer)',
    description: 'Impersonates banks or authorities in Khmer.',
    severity: 'high',
    weight: 30,
    regex: /(ធនាគារ\s*aba|ធនាគារ\s*អេស៊ីលីដា|ធនាគារ\s*វីង|អគ្គនាយកដ្ឋានពន្ធដារ|សមត្ថកិច្ច|នគរបាលជាតិ)/ui,
  },

  // 11. Suspicious Payment Instructions
  {
    id: 'TXT-PAY-INST-01',
    patternName: 'Suspicious payment instructions',
    category: 'suspicious_payment',
    title: 'Unconventional or Irreversible Payment Instructions',
    description: 'Directs payments to untraceable channels like crypto wallets, gift cards, or Western Union.',
    severity: 'high',
    weight: 30,
    regex: /\b(buy\s+(?:apple|steam|amazon|google)\s+gift\s*cards?|pay\s+via\s+(?:bitcoin|crypto|usdt|btc|western\s+union)|send\s+(?:\d+\s*)?(?:usdt|btc|crypto|bitcoin)\s+to\s+(?:wallet|address)|pay\s+via\s+western\s+union|deposit\s+to\s+(?:private|unverified)\s+account|scan\s+this\s+qr\s+to\s+pay(?:\s+me)?)\b/i,
  },
  {
    id: 'TXT-PAY-INST-KM-01',
    patternName: 'Suspicious payment instructions',
    category: 'suspicious_payment',
    title: 'Suspicious Payment Instructions (Khmer)',
    description: 'Directs payments via gift cards or crypto wallets in Khmer.',
    severity: 'high',
    weight: 30,
    regex: /(ទិញកាត\s*gift|បង់តាម\s*bitcoin|ផ្ញើតាម\s*usdt|ផ្ទេរចូលគណនីផ្ទាល់ខ្លួន)/ui,
  },

  // 12. Requests to Click Suspicious Links
  {
    id: 'TXT-LINK-01',
    patternName: 'Requests to click suspicious links',
    category: 'link_clicks',
    title: 'Solicitation to Click External / Shortened Links',
    description: 'Directly urges the recipient to click an embedded link, tap a URL, or visit a web page to resolve an issue.',
    severity: 'high',
    weight: 25,
    regex: /\b(click (here|the link|below)|tap (here|this link)|follow the link|open the link|visit http|click to (verify|confirm|claim|unlock)|check link below)\b/i,
  },
  {
    id: 'TXT-LINK-KM-01',
    patternName: 'Requests to click suspicious links',
    category: 'link_clicks',
    title: 'Link Click Solicitation (Khmer)',
    description: 'Prompts user to click links in Khmer.',
    severity: 'high',
    weight: 25,
    regex: /(ចុចទីនេះ|ចុចលើតំណភ្ជាប់|បើក link|ចុច link ខាងក្រោម|ចុចដើម្បីផ្ទៀងផ្ទាត់)/u,
  },
];

export class TextDetector {
  /**
   * Detects script type: English, Khmer, or mixed Khmer-English
   */
  detectLanguage(text: string): 'en' | 'km' | 'km-en' | 'unknown' {
    const hasKhmer = /[\u1780-\u17FF]/.test(text);
    const hasEnglish = /[a-zA-Z]/.test(text);

    if (hasKhmer && hasEnglish) return 'km-en';
    if (hasKhmer) return 'km';
    if (hasEnglish) return 'en';
    return 'unknown';
  }

  /**
   * Extracts exact suspicious phrases from the input message matching known patterns
   */
  extractSuspiciousPhrases(text: string): string[] {
    const matchedPhrases = new Set<string>();

    for (const rule of RULES) {
      const match = text.match(rule.regex);
      if (match && match[0]) {
        matchedPhrases.add(match[0].trim());
      }
    }

    return Array.from(matchedPhrases);
  }

  /**
   * Evaluates text and returns full structured scam detection results
   */
  analyzeStructured(text: string): StructuredTextScamResult {
    const language = this.detectLanguage(text);
    const suspiciousPhrases: string[] = [];
    const detectedPatterns = new Set<string>();
    const indicators: string[] = [];

    const categoryScores: Record<string, number> = {
      PHISHING: 0,
      PRIZE_SCAM: 0,
      JOB_SCAM: 0,
      INVESTMENT_SCAM: 0,
      ROMANCE_SCAM: 0,
      IMPERSONATION: 0,
      PAYMENT_SCAM: 0,
      ACCOUNT_TAKEOVER: 0,
      SOCIAL_ENGINEERING: 0,
    };

    let totalWeight = 0;
    let maxRuleWeight = 0;
    let criticalRuleCount = 0;

    for (const rule of RULES) {
      const match = text.match(rule.regex);
      if (match) {
        if (match[0]) {
          suspiciousPhrases.push(match[0].trim());
        }

        detectedPatterns.add(rule.patternName);
        indicators.push(`${rule.patternName}: ${rule.title}`);
        totalWeight += rule.weight;
        maxRuleWeight = Math.max(maxRuleWeight, rule.weight);

        if (rule.severity === 'critical') {
          criticalRuleCount++;
        }

        // Map pattern to primary categories
        switch (rule.patternName) {
          case 'Urgency':
            categoryScores.SOCIAL_ENGINEERING += rule.weight;
            categoryScores.PHISHING += Math.round(rule.weight * 0.7);
            break;
          case 'Threats':
            categoryScores.SOCIAL_ENGINEERING += rule.weight;
            categoryScores.PHISHING += Math.round(rule.weight * 0.8);
            break;
          case 'Requests for money':
            categoryScores.PAYMENT_SCAM += rule.weight;
            break;
          case 'Requests for passwords or OTPs':
            categoryScores.ACCOUNT_TAKEOVER += rule.weight;
            categoryScores.PHISHING += rule.weight;
            break;
          case 'Fake prizes':
            categoryScores.PRIZE_SCAM += rule.weight;
            break;
          case 'Fake jobs':
            categoryScores.JOB_SCAM += rule.weight;
            break;
          case 'Investment scams':
            categoryScores.INVESTMENT_SCAM += rule.weight;
            break;
          case 'Romance scams':
            categoryScores.ROMANCE_SCAM += rule.weight;
            break;
          case 'Account takeover attempts':
            categoryScores.ACCOUNT_TAKEOVER += rule.weight;
            categoryScores.PHISHING += Math.round(rule.weight * 0.8);
            break;
          case 'Impersonation':
            categoryScores.IMPERSONATION += rule.weight;
            categoryScores.PHISHING += Math.round(rule.weight * 0.7);
            break;
          case 'Suspicious payment instructions':
            categoryScores.PAYMENT_SCAM += rule.weight;
            break;
          case 'Requests to click suspicious links':
            categoryScores.PHISHING += rule.weight;
            break;
        }
      }
    }

    // Priority order: Specific scam archetype categories take precedence over generic delivery channels (PHISHING / SOCIAL_ENGINEERING)
    const SPECIFIC_CATEGORIES = [
      'PRIZE_SCAM',
      'JOB_SCAM',
      'INVESTMENT_SCAM',
      'ROMANCE_SCAM',
      'ACCOUNT_TAKEOVER',
      'PAYMENT_SCAM',
      'IMPERSONATION',
    ];

    let topCategory = 'SAFE';
    let maxCategoryScore = 0;

    for (const cat of SPECIFIC_CATEGORIES) {
      if ((categoryScores[cat] || 0) > maxCategoryScore) {
        maxCategoryScore = categoryScores[cat];
        topCategory = cat;
      }
    }

    // Fall back to generic categories if no specific scam archetype was triggered
    if (maxCategoryScore === 0) {
      for (const [cat, catScore] of Object.entries(categoryScores)) {
        if (catScore > maxCategoryScore) {
          maxCategoryScore = catScore;
          topCategory = cat;
        }
      }
    }

    // Raw threat score computed from category max and cumulative weight
    let rawScore = Math.min(100, Math.round(maxCategoryScore * 1.1 + totalWeight * 0.2));

    // Determine if message has definitive scam archetypes
    const DEFINITIVE_SCAM_PATTERNS = new Set([
      'Fake prizes',
      'Fake jobs',
      'Investment scams',
      'Romance scams',
      'Threats',
      'Requests for passwords or OTPs',
      'Account takeover attempts',
      'Suspicious payment instructions',
    ]);

    const hasDefinitiveScamPattern = Array.from(detectedPatterns).some((p) => DEFINITIVE_SCAM_PATTERNS.has(p));

    // A message is uncertain ("needs_review") when it has isolated, ambiguous indicators
    // (such as isolated urgency or a benign inquiry) without a definitive scam family.
    const isUncertain = !hasDefinitiveScamPattern && (
      (detectedPatterns.size === 1 && (detectedPatterns.has('Urgency') || detectedPatterns.has('Requests to click suspicious links'))) ||
      (rawScore <= 40 && criticalRuleCount === 0 && (topCategory === 'SOCIAL_ENGINEERING' || topCategory === 'SAFE'))
    );

    let severity: TextSeverity = 'safe';
    let finalCategory = topCategory;

    if (detectedPatterns.size === 0) {
      severity = 'safe';
      rawScore = 0;
      finalCategory = 'SAFE';
    } else if (isUncertain) {
      severity = 'needs_review';
      finalCategory = 'needs_review';
    } else if (rawScore >= 75 || criticalRuleCount >= 1) {
      severity = 'critical';
    } else if (rawScore >= 55) {
      severity = 'high';
    } else if (rawScore >= 35) {
      severity = 'medium';
    } else {
      severity = 'low';
    }

    // Confidence metric
    let confidence = 50;
    if (detectedPatterns.size >= 2) confidence += 20;
    if (criticalRuleCount > 0) confidence += 15;
    if (suspiciousPhrases.length >= 3) confidence += 10;
    if (isUncertain) confidence = 55; // Moderate confidence for uncertain / review required cases
    confidence = Math.min(99, Math.max(30, confidence));

    // Reasoning and recommended action formulation
    let reasoning = '';
    let recommendedAction = '';

    if (severity === 'safe') {
      reasoning = 'No deceptive phrasing, urgency pressure, or credential harvesting patterns were detected in the message.';
      recommendedAction = 'Message appears clean and conversational. Exercise standard digital vigilance.';
    } else if (severity === 'needs_review') {
      reasoning = `Uncertain threat signature. Detected borderline pattern (${Array.from(detectedPatterns).join(', ')}) with phrase: "${suspiciousPhrases[0] || 'N/A'}", but lacks conclusive corroborating threat evidence.`;
      recommendedAction = 'UNCERTAIN RESULT — NEEDS REVIEW: The message contains isolated or ambiguous keywords. Do not click links or send funds until independently verified through official channels.';
    } else {
      reasoning = `High-confidence malicious pattern detection. Identified ${detectedPatterns.size} distinct scam patterns (${Array.from(detectedPatterns).join(', ')}) targeting ${finalCategory}.`;
      if (detectedPatterns.has('Requests for passwords or OTPs') || detectedPatterns.has('Account takeover attempts')) {
        recommendedAction = 'CRITICAL WARNING: Never share passwords, OTP codes, or PIN numbers. Legitimate companies never request credentials via message.';
      } else if (detectedPatterns.has('Threats') || detectedPatterns.has('Impersonation')) {
        recommendedAction = 'ALERT: Coercive authority or financial institution impersonation detected. Do not reply or send money. Contact the institution directly using verified contact details.';
      } else if (detectedPatterns.has('Investment scams') || detectedPatterns.has('Fake prizes')) {
        recommendedAction = 'FRAUD WARNING: Promises of guaranteed returns, doubling crypto, or unsolicited lottery prizes are fraudulent. Do not deposit any money or pay claim fees.';
      } else {
        recommendedAction = 'Do not click embedded links, download files, or respond to this communication. Block the sender.';
      }
    }

    const summary = detectedPatterns.size > 0
      ? `Flagged ${detectedPatterns.size} suspicious pattern archetypes with ${suspiciousPhrases.length} extracted phrases.`
      : 'Message content verified clean of known social engineering patterns.';

    return {
      detected_patterns: Array.from(detectedPatterns),
      suspicious_phrases: Array.from(new Set(suspiciousPhrases)),
      scam_category: finalCategory,
      severity,
      confidence,
      evidence: {
        summary,
        indicators,
        suspicious_phrases: Array.from(new Set(suspiciousPhrases)),
        category_scores: categoryScores,
        reasoning,
      },
      recommended_action: recommendedAction,
      score: rawScore,
      language,
    };
  }

  /**
   * Evaluates text for phishing, social engineering, and scam indicators (Legacy compatibility)
   */
  analyze(text: string): TextDetectionResult {
    const structured = this.analyzeStructured(text);
    const signals: DetectionItem[] = [];

    for (const rule of RULES) {
      if (rule.regex.test(text)) {
        signals.push({
          engine: 'TextLinguisticScanner',
          category: rule.category,
          severity: rule.severity === 'critical' ? 'critical' : rule.severity === 'high' ? 'high' : 'medium',
          ruleId: rule.id,
          title: rule.title,
          description: rule.description,
        });
      }
    }

    return {
      language: structured.language,
      threatCategory: structured.scam_category === 'needs_review' ? 'UNKNOWN / NEEDS_REVIEW' : structured.scam_category,
      categoryScores: structured.evidence.category_scores,
      signals,
      detectedIndicators: structured.evidence.indicators,
      suspiciousPhrases: structured.suspicious_phrases,
      detectedPatterns: structured.detected_patterns,
      structured,
    };
  }

  /**
   * Unified detectTextThreats method
   */
  detectTextThreats(text: string) {
    const res = this.analyze(text);
    return {
      ...res,
      score: res.structured.score,
      indicators: res.detectedIndicators,
      matchedPatterns: res.detectedPatterns,
      suspiciousPhrases: res.suspiciousPhrases,
      isPhishingUrlDetected: /https?:\/\/[^\s]+/i.test(text),
      structured: res.structured,
    };
  }
}

export const textDetector = new TextDetector();
