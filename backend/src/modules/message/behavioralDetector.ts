/**
 * Pinit Behavioral Scam Pattern Detector
 * Implements detection for all 28 behavioral patterns with multi-lingual (English, Khmer, mixed) coverage.
 */

import { BehavioralPatternMatch, BehavioralPatternType, PatternSeverity } from './types';

interface BehavioralRule {
  id: string;
  patternType: BehavioralPatternType;
  patternName: string;
  severity: PatternSeverity;
  scoreContribution: number;
  title: string;
  description: string;
  regex: RegExp;
}

export class BehavioralDetector {
  private static readonly RULES: BehavioralRule[] = [
    // 1. URGENCY
    {
      id: 'BEH-01-URG',
      patternType: 'URGENCY',
      patternName: 'Urgency Pressure',
      severity: 'high',
      scoreContribution: 25,
      title: 'Manufactured Urgency & Time Pressure',
      description: 'Creates artificial time pressure to compel immediate action and bypass critical thinking.',
      regex: /(?:\b(immediately|urgent|urgently|act now|hurry|within 24 hours|within \d+ (minutes|hours)|final notice|expires? (today|soon)|before it expires|limited time only|immediate response required)\b|(បន្ទាន់|ជាបន្ទាន់|ក្នុងរយៈពេល \d+|ដំណឹងចុងក្រោយ|ផុតកំណត់ថ្ងៃនេះ))/ui,
    },

    // 2. THREATS
    {
      id: 'BEH-02-THR',
      patternType: 'THREATS',
      patternName: 'Legal & Arrest Threats',
      severity: 'critical',
      scoreContribution: 35,
      title: 'Intimidation & Law Enforcement Threats',
      description: 'Threatens police arrest, court warrants, prosecution, or legal consequences.',
      regex: /(?:\b(police warrant|arrest warrant|court summons|face arrest|lawsuit filed|legal action|criminal charges|face jail time)\b|(ជាប់គុក|ដីកាចាប់ខ្លួន|ប៉ូលីស|តុលាការ|ចាត់វិធានការច្បាប់))/ui,
    },

    // 3. ACCOUNT_SUSPENSION
    {
      id: 'BEH-03-ACT',
      patternType: 'ACCOUNT_SUSPENSION',
      patternName: 'Account Suspension Claims',
      severity: 'critical',
      scoreContribution: 35,
      title: 'False Account Suspension or Lockout Alert',
      description: 'Claims the recipient’s bank or social account is locked, suspended, or frozen.',
      regex: /(?:\b(account (?:has been|is) (?:suspended|locked|frozen|blocked|compromised|terminated)|unauthorized login detected|security lockout|reactivate your account|sign in to prevent closure|unlock your account)\b|(គណនីត្រូវបានផ្អាក|គណនីត្រូវបានចាក់សោ|រកឃើញការលួចចូល|ចុចដើម្បីដោះសោ))/ui,
    },

    // 4. FAKE_REWARDS
    {
      id: 'BEH-04-RWD',
      patternType: 'FAKE_REWARDS',
      patternName: 'Fake Rewards & Prizes',
      severity: 'high',
      scoreContribution: 30,
      title: 'Unsolicited Prize / Lottery Jackpot Lure',
      description: 'Claims unexpected monetary winnings, luxury gifts, free crypto, or lottery prizes.',
      regex: /(?:\b(congratulations|you have won|you won \$|claim your (?:prize|reward|giftcard|\$\d+)|lottery (?:winner|ticket|prize)|lucky draw winner|selected as the winner|free gift card|cash prize)\b|(សូមអបអរសាទរ|អ្នកបានឈ្នះរង្វាន់|អ្នកមានសំណាង|ទទួលរង្វាន់|ឈ្នះប្រាក់|ចាប់ឆ្នោត))/ui,
    },

    // 5. FAKE_JOBS
    {
      id: 'BEH-05-JOB',
      patternType: 'FAKE_JOBS',
      patternName: 'Fake Job Offers',
      severity: 'high',
      scoreContribution: 30,
      title: 'Deceptive Remote Task / Fake Job Recruitment',
      description: 'Offers unrealistic high daily earnings for simple tasks like video rating or review jobs.',
      regex: /(?:\b(earn \$[0-9]+ (?:per day|daily)|part-time (?:job|work)|work from home|telegram job|daily payout|like (?:youtube|tiktok) videos|daily salary \$|complete simple tasks to earn)\b|(ការងារក្រៅម៉ោង|រកចំណូលប្រចាំថ្ងៃ|ធ្វើការងារតាមទូរស័ព្ទ|មើលវីដេអូបានលុយ|ចុច like បានលុយ))/ui,
    },

    // 6. FAKE_INVESTMENTS
    {
      id: 'BEH-06-INV',
      patternType: 'FAKE_INVESTMENTS',
      patternName: 'Fake Investments & Crypto Duplication',
      severity: 'critical',
      scoreContribution: 35,
      title: 'High-Yield Investment / Crypto Doubling Fraud',
      description: 'Promises guaranteed returns, crypto doubling pools, risk-free forex, or cloud mining contracts.',
      regex: /(?:\b(guaranteed (?:returns|profit|100%|daily returns)|crypto investment|double your (?:crypto|btc|eth|money|funds)|forex trading pool|passive income guarantee|deposit usdt to double|cloud mining contract)\b|(ការវិនិយោគចំណេញ|ចំណេញ១០០%|គ្រីបតូទ្វេដង|ដាក់ប្រាក់ចំណេញ|ប្រាក់ចំណេញខ្ពស់ធានា))/ui,
    },

    // 7. FAKE_LOANS
    {
      id: 'BEH-07-LON',
      patternType: 'FAKE_LOANS',
      patternName: 'Fake Loans & Instant Credit',
      severity: 'critical',
      scoreContribution: 40,
      title: 'Predatory / Fraudulent Unsecured Loan Offer',
      description: 'Promotes instant, collateral-free loans with zero credit check to harvest advance clearance fees.',
      regex: /(?:\b(instant loan|pre-approved loan|loan approval|no collateral loan|emergency loan approved|zero credit check loan|borrow up to \$?\d+|fast cash disbursement)\b|(កម្ចីរហ័ស|កម្ចីគ្មានទ្រព្យបញ្ចាំ|អនុម័តប្រាក់កម្ចី|កម្ចីបន្ទាន់|ខ្ចីប្រាក់រហ័ស|ការប្រាក់ទាប))/ui,
    },

    // 8. FAKE_DELIVERIES
    {
      id: 'BEH-08-DLV',
      patternType: 'FAKE_DELIVERIES',
      patternName: 'Fake Deliveries & Parcel Smishing',
      severity: 'high',
      scoreContribution: 30,
      title: 'Parcel Delivery Failure / Customs Smishing',
      description: 'Falsely claims an undelivered package, missing address, or pending customs clearance fee.',
      regex: /(?:\b(package delivery failed|parcel delivery|unable to deliver your package|customs clearance pending|unpaid customs fee|shipment on hold|update your delivery address|postal service notice|dhl delivery|fedex notice)\b|(កញ្ចប់អីវ៉ាន់|មិនអាចដឹកជញ្ជូន|ជាប់គយ|បង់ថ្លៃដឹកជញ្ជូន|កែសម្រួលអាសយដ្ឋាន))/ui,
    },

    // 9. FAKE_GOVERNMENT_COMMUNICATION
    {
      id: 'BEH-09-GOV',
      patternType: 'FAKE_GOVERNMENT_COMMUNICATION',
      patternName: 'Fake Government Communication',
      severity: 'critical',
      scoreContribution: 35,
      title: 'Tax Authority / Ministerial Impersonation',
      description: 'Falsely claims to represent government tax departments, national ministries, or civic regulators.',
      regex: /(?:\b(general department of taxation|gdt cambodia|internal revenue|tax penalty|tax refund notice|ministry of post|national bank notice|customs official)\b|(អគ្គនាយកដ្ឋានពន្ធដារ|ក្រសួងប្រៃសណីយ៍|ធនាគារជាតិនៃកម្ពុជា|ពន្ធដារ))/ui,
    },

    // 10. FAKE_BANK_COMMUNICATION
    {
      id: 'BEH-10-BNK',
      patternType: 'FAKE_BANK_COMMUNICATION',
      patternName: 'Fake Bank Communication',
      severity: 'critical',
      scoreContribution: 35,
      title: 'Financial Institution / Banking Lure',
      description: 'Falsely claims to originate from banks such as ABA, Wing, ACLEDA, or Canadia Bank.',
      regex: /(?:\b(aba bank|acleda bank|wing bank|canadia bank|chase bank|bank customer service|banking security department)\b|(ធនាគារ\s*aba|ធនាគារ\s*អេស៊ីលីដា|ធនាគារ\s*វីង|ធនាគារ\s*កាណាឌីយ៉ា))/ui,
    },

    // 11. FAKE_CUSTOMER_SUPPORT
    {
      id: 'BEH-11-SPT',
      patternType: 'FAKE_CUSTOMER_SUPPORT',
      patternName: 'Fake Customer Support',
      severity: 'high',
      scoreContribution: 30,
      title: 'Imposter Helpdesk & Customer Support Representative',
      description: 'Pretends to be tech support, Telegram Help Desk, WhatsApp Support, or Meta security agents.',
      regex: /(?:\b(customer support representative|support team|help desk agent|telegram support|whatsapp support|meta support|apple support team|service agent)\b|(ផ្នែកបម្រើអតិថិជន|ក្រុមការងារបច្ចេកទេស))/ui,
    },

    // 12. ROMANCE_MANIPULATION
    {
      id: 'BEH-12-ROM',
      patternType: 'ROMANCE_MANIPULATION',
      patternName: 'Romance Manipulation & Pig Butchering',
      severity: 'high',
      scoreContribution: 30,
      title: 'Wrong-Number Pretext / Romance Icebreaker',
      description: 'Uses wrong-number pretenses, conversational flattery, or feigned intimacy to build fraudulent rapport.',
      regex: /(?:\b(sorry wrong number|are you the (?:golf coach|manager)|my assistant gave me your number|dear sweetheart|honey|let us chat privately|you seem like a kind person|nice to meet you here)\b|(សុំទោសច្រឡំលេខ|ស្គាល់គ្នាបានទេ|ជជែកគ្នាលេង))/ui,
    },

    // 13. PAYMENT_REQUESTS
    {
      id: 'BEH-13-PAY',
      patternType: 'PAYMENT_REQUESTS',
      patternName: 'Payment & Money Requests',
      severity: 'high',
      scoreContribution: 30,
      title: 'Direct Solicitation of Funds / Wire Transfers',
      description: 'Demands sending cash, wire transfers, funds transfer, or payment to specific accounts.',
      regex: /(?:\b(send (?:money|funds|cash|\$?\d+|\d+\s*(?:\$|usd|usdt|btc|eth|riel))|transfer (?:money|funds|cash|\$?\d+)|wire transfer|deposit (?:money|funds|\$?\d+)|remit funds)\b|(ផ្ទេរប្រាក់|ផ្ញើប្រាក់|បង់ប្រាក់|កក់ប្រាក់|ដាក់ប្រាក់|ផ្ញើលុយ|ផ្ទេរលុយ))/ui,
    },

    // 14. ADVANCE_FEE_REQUESTS
    {
      id: 'BEH-14-ADV',
      patternType: 'ADVANCE_FEE_REQUESTS',
      patternName: 'Advance-Fee Requests',
      severity: 'critical',
      scoreContribution: 35,
      title: 'Upfront Fee / Clearance Fee Scheme',
      description: 'Requires paying an upfront deposit, release fee, or clearance charge before receiving promised assets.',
      regex: /(?:\b(pay (?:upfront|fee|deposit|processing fee|clearance fee|release fee|activation fee)|advance deposit required|fee must be paid first|pay tax before withdrawal)\b|(បង់ថ្លៃសេវាជាមុន|កក់ប្រាក់ជាមុន|បង់ពន្ធមុននឹងដកប្រាក់))/ui,
    },

    // 15. OTP_REQUESTS
    {
      id: 'BEH-15-OTP',
      patternType: 'OTP_REQUESTS',
      patternName: 'OTP / Verification Code Harvesting',
      severity: 'critical',
      scoreContribution: 40,
      title: 'One-Time Verification Code Solicitation',
      description: 'Directly asks for one-time verification tokens (OTP), SMS authentication codes, or authorization digits.',
      regex: /(?:\b(?:(?:enter|send|reply with|share|provide)(?: me| us| your)? (?:this |the )?(?:\d+-digit )?(?:otp|code|one-time password|verification code|passcode)|what is the (?:otp|code)|plz send (?:me )?(?:the )?\d+-digit code)\b|(?:កូដ otp|លេខកូដសម្ងាត់|ផ្ញើកូដ otp|លេខផ្ទៀងផ្ទាត់|ផ្ញើលេខកូដ))/ui,
    },

    // 16. PASSWORD_REQUESTS
    {
      id: 'BEH-16-PWD',
      patternType: 'PASSWORD_REQUESTS',
      patternName: 'Password Requests',
      severity: 'critical',
      scoreContribution: 40,
      title: 'Explicit Account Password Solicitation',
      description: 'Solicits user passwords, passcodes, or account master credentials.',
      regex: /(?:\b(enter your password|send (?:your|the) password|provide your login password|verify your password|password confirmation needed)\b|(ពាក្យសម្ងាត់|ផ្ញើពាក្យសម្ងាត់))/ui,
    },

    // 17. PIN_REQUESTS
    {
      id: 'BEH-17-PIN',
      patternType: 'PIN_REQUESTS',
      patternName: 'PIN Code Requests',
      severity: 'critical',
      scoreContribution: 40,
      title: 'ATM / Banking PIN Solicitation',
      description: 'Asks for numeric personal identification numbers (PIN) for bank or mobile wallet access.',
      regex: /(?:\b(enter your pin|4-digit pin|provide your atm pin|bank pin code|verify your pin)\b|(លេខសម្ងាត់ pin|លេខកូដសម្ងាត់ ៤ខ្ទង់))/ui,
    },

    // 18. BANKING_CREDENTIAL_REQUESTS
    {
      id: 'BEH-18-BCR',
      patternType: 'BANKING_CREDENTIAL_REQUESTS',
      patternName: 'Banking & Card Credential Requests',
      severity: 'critical',
      scoreContribution: 40,
      title: 'Payment Card / CVV / Banking Login Harvesting',
      description: 'Requests full credit/debit card numbers, CVV security codes, expiration dates, or bank login credentials.',
      regex: /(?:\b(enter (?:card number|cvv|cvc|card security code)|credit card details|banking credentials|debit card expiration|provide bank login)\b|(លេខកាត|លេខសម្ងាត់ cvv))/ui,
    },

    // 19. IDENTITY_DOCUMENT_REQUESTS
    {
      id: 'BEH-19-IDD',
      patternType: 'IDENTITY_DOCUMENT_REQUESTS',
      patternName: 'Identity Document Requests',
      severity: 'high',
      scoreContribution: 30,
      title: 'Government ID / Passport / Selfie Harvesting',
      description: 'Requests copies of national identity cards, passports, or selfies holding identity documents.',
      regex: /(?:\b(send (?:photo of|copy of) (?:id card|passport|driver'?s license)|selfie with id|upload national identity)\b|(ថតរូបអត្តសញ្ញាណប័ណ្ណ|លិខិតឆ្លងដែន|ថតរូបជាមួយអត្តសញ្ញាណប័ណ្ណ))/ui,
    },

    // 20. REMOTE_ACCESS_REQUESTS
    {
      id: 'BEH-20-RMT',
      patternType: 'REMOTE_ACCESS_REQUESTS',
      patternName: 'Remote Access Requests',
      severity: 'critical',
      scoreContribution: 40,
      title: 'Remote Desktop / Screen Sharing Solicitation',
      description: 'Instructs victims to install remote access tools like AnyDesk, TeamViewer, or QuickSupport.',
      regex: /(?:\b(install anydesk|download teamviewer|install quicksupport|ultraviewer|grant remote access|allow screen sharing|remote control session)\b|(ដំឡើង anydesk|ដំឡើង teamviewer))/ui,
    },

    // 21. SUSPICIOUS_DOWNLOADS
    {
      id: 'BEH-21-DWN',
      patternType: 'SUSPICIOUS_DOWNLOADS',
      patternName: 'Suspicious Software & APK Downloads',
      severity: 'critical',
      scoreContribution: 35,
      title: 'Unverified APK / Executable Software Lure',
      description: 'Encourages sideloading unverified Android APK packages or running executable files.',
      regex: /(?:\b(download apk|install this app|download (?:update|software|app)|run .exe|install profile|download attachment to update)\b|(ទាញយក apk|ដំឡើងកម្មវិធី|ទាញយកឯកសារ))/ui,
    },

    // 22. SUSPICIOUS_LINKS
    {
      id: 'BEH-22-LNK',
      patternType: 'SUSPICIOUS_LINKS',
      patternName: 'Suspicious Link Clicks',
      severity: 'high',
      scoreContribution: 25,
      title: 'Urgent Link Redirection Solicitation',
      description: 'Strongly urges the victim to click embedded links to resolve warnings or claim benefits.',
      regex: /(?:\b(click (?:here|the link|below|to verify|to confirm|to claim|to unlock)|tap (?:here|this link)|follow the link|open the link|check link below)\b|(ចុចទីនេះ|ចុចលើតំណភ្ជាប់|បើក link|ចុច link ខាងក្រោម))/ui,
    },

    // 23. IMPERSONATION
    {
      id: 'BEH-23-IMP',
      patternType: 'IMPERSONATION',
      patternName: 'Brand & Corporate Impersonation',
      severity: 'high',
      scoreContribution: 30,
      title: 'Trusted Entity / Authority Impersonation',
      description: 'Claims affiliation with well-known brands, executive officers, or trusted organizations.',
      regex: /(?:\b(official (?:support|representative|notice)|on behalf of (?:apple|google|meta|paypal|binance)|ceo of|security department of)\b|(តំណាងផ្លូវការ))/ui,
    },

    // 24. FINANCIAL_MANIPULATION
    {
      id: 'BEH-24-FNM',
      patternType: 'FINANCIAL_MANIPULATION',
      patternName: 'Financial Manipulation & Overpayment',
      severity: 'high',
      scoreContribution: 30,
      title: 'Overpayment / Accidental Transfer / Refund Scheme',
      description: 'Falsely claims an accidental transfer was made or shows forged receipts demanding a refund.',
      regex: /(?:\b(accidentally sent you|refund the excess|overpaid you|sent funds by mistake|confirm refund payment|send back the extra money)\b|(ផ្ទេរប្រាក់ច្រឡំ|សូមផ្ទេរត្រឡប់មកវិញ))/ui,
    },

    // 25. FEAR_BASED_MANIPULATION
    {
      id: 'BEH-25-FER',
      patternType: 'FEAR_BASED_MANIPULATION',
      patternName: 'Fear-Based Manipulation',
      severity: 'critical',
      scoreContribution: 35,
      title: 'Panic & Asset Confiscation Coercion',
      description: 'Manufactures panic by threatening asset forfeiture, permanent blacklisting, or financial ruination.',
      regex: /(?:\b(all funds will be confiscated|funds seized|blacklist your name|ruin your credit|severe penalties will apply|permanent damage to your account)\b|(ទ្រព្យសម្បត្តិត្រូវបានរឹបអូស|ដាក់ក្នុងបញ្ជីខ្មៅ))/ui,
    },

    // 26. AUTHORITY_IMPERSONATION
    {
      id: 'BEH-26-AUT',
      patternType: 'AUTHORITY_IMPERSONATION',
      patternName: 'Authority & Law Enforcement Impersonation',
      severity: 'critical',
      scoreContribution: 35,
      title: 'Law Enforcement / Judicial Impersonation',
      description: 'Impersonates high-ranking law enforcement officers, cybercrime police, prosecutors, or judges.',
      regex: /(?:\b(cyber crime (?:unit|investigator)|police officer|detective|lieutenant|prosecutor office|court official|national security officer)\b|(មន្ត្រីនគរបាល|សមត្ថកិច្ច|ព្រះរាជអាជ្ញា))/ui,
    },

    // 27. EXCESSIVE_URGENCY
    {
      id: 'BEH-27-XUR',
      patternType: 'EXCESSIVE_URGENCY',
      patternName: 'Excessive Urgency & Ultimatums',
      severity: 'critical',
      scoreContribution: 35,
      title: 'Strict Ultimatums & Short-Fuse Deadlines',
      description: 'Imposes extreme, countdown-style ultimatums (e.g. within 10 minutes) to paralyze deliberation.',
      regex: /(?:\b(within (?:5|10|15|30) minutes|in the next \d+ minutes|you have \d+ minutes remaining|countdown timer|do not delay a second|immediate action before midnight)\b|(ក្នុងរយៈពេល \d+ នាទី|បន្ទាន់បំផុត))/ui,
    },

    // 28. REQUESTS_TO_MOVE_PLATFORM
    {
      id: 'BEH-28-MOV',
      patternType: 'REQUESTS_TO_MOVE_PLATFORM',
      patternName: 'Requests to Move Off-Platform',
      severity: 'high',
      scoreContribution: 25,
      title: 'Off-Platform Messenger Diversion',
      description: 'Attempts to divert communication to external private channels like WhatsApp, Telegram, or Line.',
      regex: /(?:\b(chat on (?:whatsapp|telegram|line)|add my (?:whatsapp|telegram|line)|message me on (?:whatsapp|telegram|line)|let'?s talk on (?:whatsapp|telegram)|join (?:my|the) telegram (?:group|channel))\b|(ជជែកគ្នាតាម (?:telegram|whatsapp)|ទាក់ទងតាម telegram))/ui,
    },
  ];

  /**
   * Evaluates text against all 28 behavioral rules and extracts matched phrases
   */
  detect(cleanedText: string, deobfuscatedText: string): BehavioralPatternMatch[] {
    const matches: BehavioralPatternMatch[] = [];

    for (const rule of BehavioralDetector.RULES) {
      const matchedPhrases = new Set<string>();

      // Test against clean text
      const cleanMatch = cleanedText.match(rule.regex);
      if (cleanMatch) {
        matchedPhrases.add(cleanMatch[0].trim());
      }

      // Test against deobfuscated text
      const deobfMatch = deobfuscatedText.match(rule.regex);
      if (deobfMatch) {
        matchedPhrases.add(deobfMatch[0].trim());
      }

      if (matchedPhrases.size > 0) {
        matches.push({
          id: rule.id,
          patternType: rule.patternType,
          patternName: rule.patternName,
          severity: rule.severity,
          scoreContribution: rule.scoreContribution,
          title: rule.title,
          description: rule.description,
          matchedPhrases: Array.from(matchedPhrases),
        });
      }
    }

    return matches;
  }
}

export const behavioralDetector = new BehavioralDetector();
