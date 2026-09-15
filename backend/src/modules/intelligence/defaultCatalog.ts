import { CreatePatternInput } from './types';

export const DEFAULT_SCAM_PATTERNS: Array<CreatePatternInput & { id?: string }> = [
  // =========================================================================
  // 1. Phishing
  // =========================================================================
  {
    id: 'intel-phish-001',
    category: 'phishing',
    pattern: '\\b(urgent security update|click here to verify your (account|identity)|unauthorized login detected|confirm your details)\\b',
    severity: 'high',
    description: 'Deceptive lure to induce victims to enter credentials on fraudulent verification portals.',
    source: 'apwg_threat_intel',
    status: 'active',
  },
  {
    id: 'intel-phish-002',
    category: 'phishing',
    pattern: '\\b(your mailbox is full|storage quota exceeded|re-authenticate to prevent suspension)\\b',
    severity: 'medium',
    description: 'Phishing campaign targeting email inbox credentials via fake quota warnings.',
    source: 'cisa_advisory',
    status: 'active',
  },
  {
    id: 'intel-phish-km-001',
    category: 'phishing',
    pattern: '(ចុចទីនេះដើម្បីបញ្ជាក់|ផ្ទៀងផ្ទាត់គណនីរបស់អ្នក|ការចូលប្រើប្រាស់ដោយគ្មានការអនុញ្ញាត)',
    severity: 'high',
    description: 'Phishing credential harvesting portal lure in Khmer.',
    source: 'cambodia_cert_alert',
    status: 'active',
  },

  // =========================================================================
  // 2. Fake Investment
  // =========================================================================
  {
    id: 'intel-invest-001',
    category: 'fake_investment',
    pattern: '\\b(guaranteed (daily|weekly|monthly) profit|risk-free high yield|(100%|200%|300%) returns guaranteed|vip investment tier|exclusive insider trading)\\b',
    severity: 'critical',
    description: 'Ponzi or fake high-yield investment scheme promising impossible risk-free returns.',
    source: 'sec_investor_alert',
    status: 'active',
  },
  {
    id: 'intel-invest-002',
    category: 'fake_investment',
    pattern: '\\b(automated trading bot earns \\$\\d+|passive income system|deposit \\$\\d+ earn \\$\\d+ today)\\b',
    severity: 'high',
    description: 'Automated forex/bot investment lure designed to harvest initial deposit funds.',
    source: 'ftc_consumer_alert',
    status: 'active',
  },
  {
    id: 'intel-invest-km-001',
    category: 'fake_investment',
    pattern: '(ធានាចំណេញ១០០%|វិនិយោគចំណេញខ្ពស់|ប្រាក់ចំណេញធានា|ដាក់ប្រាក់ចំណេញទ្វេដង|គ្មានហានិភ័យ)',
    severity: 'critical',
    description: 'High-yield fake investment and Ponzi lure in Khmer.',
    source: 'cambodia_cert_alert',
    status: 'active',
  },

  // =========================================================================
  // 3. Fake Job
  // =========================================================================
  {
    id: 'intel-job-001',
    category: 'fake_job',
    pattern: '\\b(part-time (job|work)|earn \\$[1-9]\\d{1,3}\\s?(daily|per day)|like (youtube|tiktok) videos to earn|complete simple daily tasks|vip task recharge)\\b',
    severity: 'high',
    description: 'Task scam or fake work-from-home position asking victims to deposit money or complete fake rating tasks.',
    source: 'interpol_financial_crimes',
    status: 'active',
  },
  {
    id: 'intel-job-002',
    category: 'fake_job',
    pattern: '\\b(hiring immediately no interview|work 30 minutes daily earn \\$\\d+|data entry clerk remote no experience)\\b',
    severity: 'medium',
    description: 'Remote work advance-fee recruitment lure.',
    source: 'bbb_scam_tracker',
    status: 'active',
  },
  {
    id: 'intel-job-km-001',
    category: 'fake_job',
    pattern: '(ការងារក្រៅម៉ោង|រកចំណូលប្រចាំថ្ងៃ|ធ្វើការងារតាមទូរស័ព្ទ|មើលវីដេអូបានលុយ|ប្រាក់បៀវត្សរ៍ប្រចាំថ្ងៃ|បញ្ចូលលុយដើម្បីបំពេញភារកិច្ច)',
    severity: 'high',
    description: 'Task-based recruitment and video rating fraud in Khmer.',
    source: 'internal_research',
    status: 'active',
  },

  // =========================================================================
  // 4. Romance Scam
  // =========================================================================
  {
    id: 'intel-romance-001',
    category: 'romance_scam',
    pattern: '\\b(sorry wrong number|let\'s chat on (whatsapp|telegram)|my assistant gave me this number|invest with my uncle|exclusive trading platform|financial freedom together)\\b',
    severity: 'high',
    description: 'Sha Zhu Pan (Pig Butchering) romance lure initiating relationship grooming leading to fraudulent crypto/forex platforms.',
    source: 'fbi_ic3_advisory',
    status: 'active',
  },
  {
    id: 'intel-romance-002',
    category: 'romance_scam',
    pattern: '\\b(i love you dearly|need money for plane ticket|medical emergency in hospital overseas|customs clearance for gift sent to you)\\b',
    severity: 'high',
    description: 'Classic advance-fee romance fraud requesting emergency medical or parcel customs fees.',
    source: 'ftc_consumer_alert',
    status: 'active',
  },
  {
    id: 'intel-romance-km-001',
    category: 'romance_scam',
    pattern: '(សុំទោសច្រឡំលេខ|ឆាតតាមតេឡេក្រាម|វិនិយោគជាមួយពូខ្ញុំ|ជួយផ្ញើប្រាក់ថ្លៃសំបុត្រយន្តហោះ|កញ្ចប់អំណោយជាប់គយ)',
    severity: 'high',
    description: 'Pig butchering and advance-fee romance fraud in Khmer.',
    source: 'cambodia_cert_alert',
    status: 'active',
  },

  // =========================================================================
  // 5. Payment Scam
  // =========================================================================
  {
    id: 'intel-pay-001',
    category: 'payment_scam',
    pattern: '\\b(accidental overpayment|i sent you extra money by mistake|refund the difference via (zelle|venmo|wire|gift card)|fake payment confirmation screenshot)\\b',
    severity: 'high',
    description: 'Overpayment scheme with fraudulent payment confirmation or bounced check asking for refund of difference.',
    source: 'cfpb_consumer_bulletin',
    status: 'active',
  },
  {
    id: 'intel-pay-002',
    category: 'payment_scam',
    pattern: '\\b(pay via (steam|apple|itunes|google play|razer gold) gift card|send payment to personal account to avoid tax)\\b',
    severity: 'critical',
    description: 'Untraceable gift card payment demand for settling bills, fines, or purchases.',
    source: 'ftc_consumer_alert',
    status: 'active',
  },
  {
    id: 'intel-pay-km-001',
    category: 'payment_scam',
    pattern: '(ផ្ទេរប្រាក់ច្រឡំ|ផ្ញើប្រាក់លើស|ជួយផ្ញើប្រាក់ត្រឡប់មកវិញ|បង់ប្រាក់តាមកាតកាដូ)',
    severity: 'high',
    description: 'Accidental overpayment and gift card payment demands in Khmer.',
    source: 'internal_research',
    status: 'active',
  },

  // =========================================================================
  // 6. Account Takeover
  // =========================================================================
  {
    id: 'intel-ato-001',
    category: 'account_takeover',
    pattern: '\\b(send (me )?(the )?((6|4)-digit\\s*)?(verification|security|authentication|sms|otp)?\\s*code|share your (authentication|verification) code|don\'t share this (code|otp) with anyone)\\b',
    severity: 'critical',
    description: 'Direct SMS OTP / MFA token interception request to compromise and hijack online accounts.',
    source: 'cisa_advisory',
    status: 'active',
  },
  {
    id: 'intel-ato-002',
    category: 'account_takeover',
    pattern: '\\b(your account password has expired|update your 2fa settings immediately|reset your password here to prevent permanent termination)\\b',
    severity: 'high',
    description: 'Credential and 2FA hijack vector simulating account expiration warnings.',
    source: 'apwg_threat_intel',
    status: 'active',
  },
  {
    id: 'intel-ato-km-001',
    category: 'account_takeover',
    pattern: '(ផ្ញើលេខកូដ otp|ផ្ញើលេខកូដ ៦ ខ្ទង់|កុំប្រាប់លេខកូដនេះទៅអ្នកណា|ផ្ទៀងផ្ទាត់លេខកូដសម្ងាត់)',
    severity: 'critical',
    description: 'SMS OTP interception and unauthorized account takeover lure in Khmer.',
    source: 'cambodia_cert_alert',
    status: 'active',
  },

  // =========================================================================
  // 7. Impersonation
  // =========================================================================
  {
    id: 'intel-imper-001',
    category: 'impersonation',
    pattern: '\\b(aba bank|wing bank|acleda|canadia|paypal|chase|wells fargo|internal revenue service|tax authority|police department|federal bureau of investigation)\\b.*\\b(unauthorized transaction|account suspended|locked|verify now|fraud alert|arrest warrant)\\b',
    severity: 'critical',
    description: 'Bank, financial institution, police, or tax authority impersonation creating extreme urgency and intimidation.',
    source: 'cisa_advisory',
    status: 'active',
  },
  {
    id: 'intel-imper-002',
    category: 'impersonation',
    pattern: '\\b(this is ceo|i am in a meeting|urgently buy gift cards for client|confidential wire transfer request)\\b',
    severity: 'high',
    description: 'Business Email Compromise (BEC) and executive executive impersonation.',
    source: 'fbi_ic3_advisory',
    status: 'active',
  },
  {
    id: 'intel-imper-km-001',
    category: 'impersonation',
    pattern: '(ធនាគារ\\s?(aba|វីង|អេស៊ីលីដា|កាណាឌីយ៉ា)|សមត្ថកិច្ច|នគរបាល|តុលាការ).*(ផ្អាក|បិទ|ផ្ទៀងផ្ទាត់|លួចចូល|ដីកាចាប់ខ្លួន)',
    severity: 'critical',
    description: 'Local Cambodian bank and law enforcement impersonation in Khmer.',
    source: 'cambodia_cert_alert',
    status: 'active',
  },

  // =========================================================================
  // 8. Lottery Scam
  // =========================================================================
  {
    id: 'intel-lottery-001',
    category: 'lottery_scam',
    pattern: '\\b(congratulations|you have won|winner of|lucky draw winner|claim your (prize|reward|giftcard|\\$\\d{3,}))\\b.*\\b(pay (shipping|processing|clearance|tax) fee)\\b',
    severity: 'high',
    description: 'Advance-fee lottery and prize scam requiring fee/tax payment before claiming fictitious winnings.',
    source: 'ftc_consumer_alert',
    status: 'active',
  },
  {
    id: 'intel-lottery-002',
    category: 'lottery_scam',
    pattern: '\\b(your ticket number was selected in the international sweepstakes|unclaimed inheritance of \\$\\d+ million)\\b',
    severity: 'medium',
    description: 'International sweepstakes and fake inheritance advance-fee notification.',
    source: 'interpol_financial_crimes',
    status: 'active',
  },
  {
    id: 'intel-lottery-km-001',
    category: 'lottery_scam',
    pattern: '(សូមអបអរសាទរ|អ្នកបានឈ្នះរង្វាន់|អ្នកមានសំណាង|ទទួលរង្វាន់|ឈ្នះប្រាក់).*(ផ្ញើប្រាក់សេវា|បង់ពន្ធ|មុនពេលបើករង្វាន់)',
    severity: 'high',
    description: 'Lottery prize advance-fee clearance scam in Khmer.',
    source: 'internal_research',
    status: 'active',
  },

  // =========================================================================
  // 9. Cryptocurrency Scam
  // =========================================================================
  {
    id: 'intel-crypto-001',
    category: 'cryptocurrency_scam',
    pattern: '\\b(send (0\\.\\d+|[1-9]\\d*)\\s?(btc|eth|usdt|bnb|sol)\\s?(and|to)?\\s?get|double your (crypto|btc|eth|bitcoin)|giveaway (btc|eth)|airdrop claim connect wallet)\\b',
    severity: 'critical',
    description: 'Cryptocurrency doubling scheme, fraudulent wallet drainer, or fake token airdrop.',
    source: 'chainalysis_threat_report',
    status: 'active',
  },
  {
    id: 'intel-crypto-002',
    category: 'cryptocurrency_scam',
    pattern: '\\b(enter your 12-word seed phrase|input private key to sync wallet|metamask verification required)\\b',
    severity: 'critical',
    description: 'Direct mnemonic seed phrase or private key theft targeting Web3 crypto wallets.',
    source: 'cert_crypto_alert',
    status: 'active',
  },
  {
    id: 'intel-crypto-km-001',
    category: 'cryptocurrency_scam',
    pattern: '(ផ្ញើ btc ទទួលបានទ្វេដង|គ្រីបតូឥតគិតថ្លៃ|បញ្ចូលពាក្យសម្ងាត់កាបូបលុយ|តភ្ជាប់កាបូបលុយទទួល airdrop)',
    severity: 'critical',
    description: 'Cryptocurrency giveaway and wallet seed phrase harvesting in Khmer.',
    source: 'cambodia_cert_alert',
    status: 'active',
  },

  // =========================================================================
  // 10. Tech-Support Scam
  // =========================================================================
  {
    id: 'intel-tech-001',
    category: 'tech_support_scam',
    pattern: '\\b(windows defender alert|microsoft certified technician|apple security center|call toll-free \\+?1?[-.\\s]?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}|your computer is infected with trojan)\\b',
    severity: 'critical',
    description: 'Fake system crash alert or pop-up instructing victims to call a fraudulent tech support hotline.',
    source: 'microsoft_digital_crimes_unit',
    status: 'active',
  },
  {
    id: 'intel-tech-002',
    category: 'tech_support_scam',
    pattern: '\\b(download anydesk to fix your pc|install teamviewer for diagnostic|remote access required to remove virus)\\b',
    severity: 'high',
    description: 'Remote access tool manipulation used by fraudulent technicians to access online banking.',
    source: 'cisa_advisory',
    status: 'active',
  },
  {
    id: 'intel-tech-km-001',
    category: 'tech_support_scam',
    pattern: '(កុំព្យូទ័ររបស់អ្នកមានមេរោគ|ទូរស័ព្ទទៅកាន់ផ្នែកបច្ចេកទេស|ដំឡើងកម្មវិធី anydesk|ចូលបញ្ជាពីចម្ងាយ)',
    severity: 'high',
    description: 'Fake virus alert demanding remote connection in Khmer.',
    source: 'internal_research',
    status: 'active',
  },
];
