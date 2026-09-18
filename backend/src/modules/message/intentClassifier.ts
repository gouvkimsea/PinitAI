/**
 * Pinit Message Intent Classifier
 * Determines the primary communicative intent of the message based on
 * behavioral patterns, extracted entities, and social engineering context.
 */

import { BehavioralPatternMatch, ExtractedEntities, MessageIntentClassification } from './types';

export class IntentClassifier {
  /**
   * Classifies message communicative intent
   */
  classify(
    patterns: BehavioralPatternMatch[],
    entities: ExtractedEntities,
    _cleanedText: string
  ): MessageIntentClassification {
    const patternTypes = new Set(patterns.map((p) => p.patternType));

    // 1. Credential / Account Harvesting
    if (
      patternTypes.has('OTP_REQUESTS') ||
      patternTypes.has('PASSWORD_REQUESTS') ||
      patternTypes.has('PIN_REQUESTS') ||
      patternTypes.has('BANKING_CREDENTIAL_REQUESTS') ||
      entities.requestedCredentials.length > 0
    ) {
      return {
        primaryIntent: 'CREDENTIAL_HARVESTING',
        confidence: 90,
        isSolicitation: true,
        summary: 'Intent to harvest user credentials, one-time verification passwords (OTP), or banking authentication codes.',
      };
    }

    // 2. Remote Access Software Takeover
    if (patternTypes.has('REMOTE_ACCESS_REQUESTS')) {
      return {
        primaryIntent: 'REMOTE_ACCESS_ATTEMPT',
        confidence: 95,
        isSolicitation: true,
        summary: 'Intent to gain unauthorized remote desktop control over the victim’s computer or mobile device.',
      };
    }

    // 3. Advance-Fee / Upfront Charge Fraud
    if (patternTypes.has('ADVANCE_FEE_REQUESTS')) {
      return {
        primaryIntent: 'FINANCIAL_ADVANCE_FEE',
        confidence: 85,
        isSolicitation: true,
        summary: 'Intent to elicit an upfront clearance fee, deposit, or administrative charge before releasing fictitious funds or goods.',
      };
    }

    // 4. Delivery / Parcel Smishing
    if (patternTypes.has('FAKE_DELIVERIES')) {
      return {
        primaryIntent: 'DELIVERY_SMISHING',
        confidence: 85,
        isSolicitation: true,
        summary: 'Intent to lure recipient into clicking links or paying fees under the guise of an undelivered parcel or customs hold.',
      };
    }

    // 5. Predatory / Fake Loan
    if (patternTypes.has('FAKE_LOANS')) {
      return {
        primaryIntent: 'LOAN_SOLICITATION',
        confidence: 85,
        isSolicitation: true,
        summary: 'Intent to deceive the recipient with an unverified, instant loan offer to extract personal data or upfront deposits.',
      };
    }

    // 6. Fake Investment / Crypto Scheme
    if (patternTypes.has('FAKE_INVESTMENTS')) {
      return {
        primaryIntent: 'INVESTMENT_SOLICITATION',
        confidence: 85,
        isSolicitation: true,
        summary: 'Intent to solicit financial deposits into fraudulent high-yield cryptocurrency or trading schemes.',
      };
    }

    // 7. Fake Remote Job / Task Recruitment
    if (patternTypes.has('FAKE_JOBS')) {
      return {
        primaryIntent: 'DECEPTIVE_JOB_RECRUITMENT',
        confidence: 85,
        isSolicitation: true,
        summary: 'Intent to recruit recipient into task-based remote work scams with deceptive daily payout promises.',
      };
    }

    // 8. Fake Lottery / Prize Award
    if (patternTypes.has('FAKE_REWARDS')) {
      return {
        primaryIntent: 'PRIZE_CLAIM',
        confidence: 85,
        isSolicitation: true,
        summary: 'Intent to induce the victim to claim non-existent lottery prizes, gift cards, or sweepstakes winnings.',
      };
    }

    // 9. Authority Coercion & Legal Threats
    if (
      patternTypes.has('THREATS') ||
      patternTypes.has('AUTHORITY_IMPERSONATION') ||
      patternTypes.has('FEAR_BASED_MANIPULATION')
    ) {
      return {
        primaryIntent: 'AUTHORITY_COERCION',
        confidence: 85,
        isSolicitation: true,
        summary: 'Intent to intimidate the recipient through fear of arrest, court prosecution, or official asset confiscation.',
      };
    }

    // 10. Customer Support Impersonation / Account Alert
    if (
      patternTypes.has('ACCOUNT_SUSPENSION') ||
      patternTypes.has('FAKE_CUSTOMER_SUPPORT') ||
      patternTypes.has('FAKE_BANK_COMMUNICATION') ||
      patternTypes.has('FAKE_GOVERNMENT_COMMUNICATION')
    ) {
      return {
        primaryIntent: 'CUSTOMER_SUPPORT_IMPOSTER',
        confidence: 80,
        isSolicitation: true,
        summary: 'Intent to impersonate an official service desk or banking support team to manipulate account security.',
      };
    }

    // 11. Romance / Wrong-Number Lure
    if (patternTypes.has('ROMANCE_MANIPULATION')) {
      return {
        primaryIntent: 'ROMANCE_ICEBREAKER',
        confidence: 80,
        isSolicitation: true,
        summary: 'Intent to initiate unsolicited conversational rapport via wrong-number pretexting for subsequent social engineering.',
      };
    }

    // 12. Off-Platform Messenger Diversion
    if (patternTypes.has('REQUESTS_TO_MOVE_PLATFORM')) {
      return {
        primaryIntent: 'OFF_PLATFORM_LURE',
        confidence: 70,
        isSolicitation: true,
        summary: 'Intent to divert the conversation to unmonitored external messaging channels (Telegram/WhatsApp).',
      };
    }

    // 13. Isolated Urgency or Isolated Link
    if (patternTypes.has('URGENCY') || patternTypes.has('SUSPICIOUS_LINKS')) {
      return {
        primaryIntent: 'UNKNOWN_AMBIGUOUS',
        confidence: 45,
        isSolicitation: true,
        summary: 'Ambiguous solicitation containing urgency cues or link requests without a definitive scam archetype.',
      };
    }

    // 14. Clean / Conversational
    if (patterns.length === 0) {
      return {
        primaryIntent: 'BENIGN_CONVERSATION',
        confidence: 90,
        isSolicitation: false,
        summary: 'Standard conversational communication devoid of unsolicited commercial, credential, or financial solicitations.',
      };
    }

    return {
      primaryIntent: 'UNKNOWN_AMBIGUOUS',
      confidence: 50,
      isSolicitation: false,
      summary: 'Mixed or ambiguous intent lacking definitive threat archetype confirmation.',
    };
  }
}

export const intentClassifier = new IntentClassifier();
