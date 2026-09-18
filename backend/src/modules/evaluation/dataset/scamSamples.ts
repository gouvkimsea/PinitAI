import { EvaluationSample } from './types';

export const SCAM_SAMPLES: EvaluationSample[] = [
  // =========================================================================
  // 1. Phishing
  // =========================================================================
  {
    id: 'SCAM-PHISH-EN-001',
    content: 'Security Alert: Your Microsoft 365 mailbox has exceeded storage quota. Re-verify your credentials within 24h to avoid deletion: https://outlook-verify-security.live.security-portal.xyz',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'phishing',
    language: 'en',
    nuanceTags: ['high_urgency', 'unusual_domain'],
    difficulty: 'subtle',
    description: 'Corporate mailbox quota phishing with subdomain spoofing.',
    extractedUrls: ['https://outlook-verify-security.live.security-portal.xyz'],
  },
  {
    id: 'SCAM-PHISH-KM-001',
    content: 'ការជូនដំណឹងសុវត្ថិភាព៖ ប្រព័ន្ធបានរកឃើញការចូលមិនប្រក្រតី។ សូមចុចតំណភ្ជាប់ដើម្បីផ្ទៀងផ្ទាត់គណនីរបស់អ្នកឡើងវិញជាបន្ទាន់ https://security-verify-km.net/auth',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'phishing',
    language: 'km',
    nuanceTags: ['high_urgency'],
    difficulty: 'subtle',
    description: 'Khmer security notice phishing lure with unverified domain.',
    extractedUrls: ['https://security-verify-km.net/auth'],
  },
  {
    id: 'SCAM-PHISH-MIX-001',
    content: 'Urgent plzz! គណនី Facebook របស់អ្នកត្រូវបានគេ report. Plz verify ownership here before account lock: https://fb-support-case982.site/review',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'phishing',
    language: 'km-en',
    nuanceTags: ['slang_shorthand', 'mixed_script', 'misspellings'],
    difficulty: 'adversarial',
    description: 'Khmer-English mixed copyright infringement Facebook lure with slang ("plzz").',
    extractedUrls: ['https://fb-support-case982.site/review'],
  },

  // =========================================================================
  // 2. Fake Banking Messages
  // =========================================================================
  {
    id: 'SCAM-BANK-EN-001',
    content: 'ABA Bank: A transaction of $4,500 to account **8921 is pending. If this was NOT you, cancel immediately at https://aba-online-cancel.com/void',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_banking',
    language: 'en',
    nuanceTags: ['high_urgency'],
    difficulty: 'subtle',
    description: 'Fake bank fraud alert tricking user into cancelling fake transaction.',
    extractedUrls: ['https://aba-online-cancel.com/void'],
  },
  {
    id: 'SCAM-BANK-KM-001',
    content: 'ធនាគារអេស៊ីលីដា (ACLEDA Bank): គណនីរបស់អ្នកត្រូវបានផ្អាកជាបណ្ដោះអាសន្ន។ សូមចូលទៅកាន់ https://acleda-mobile-verify.com ដើម្បីធ្វើបច្ចុប្បន្នភាពព័ត៌មាន។',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_banking',
    language: 'km',
    nuanceTags: ['high_urgency'],
    difficulty: 'subtle',
    description: 'Fake ACLEDA bank suspension notice in Khmer with typo domain.',
    extractedUrls: ['https://acleda-mobile-verify.com'],
  },

  // =========================================================================
  // 3. Fake Payment Requests
  // =========================================================================
  {
    id: 'SCAM-PAY-EN-001',
    content: 'Oops! I accidentally sent you $1,200 via Zelle instead of my contractor. Can you please wire it back via Western Union or Apple gift cards ASAP? Plz dont steal it!',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_payment',
    language: 'en',
    nuanceTags: ['slang_shorthand', 'high_urgency'],
    difficulty: 'adversarial',
    description: 'Accidental payment refund scam requesting gift cards or wire transfer.',
  },
  {
    id: 'SCAM-PAY-KM-001',
    content: 'សួស្តីបង! ខ្ញុំបានផ្ទេរប្រាក់ច្រឡំចូលគណនីបងចំនួន $800។ សូមបងជួយទិញកាត Apple Gift Card សងខ្ញុំវិញផងព្រោះខ្ញុំត្រូវការព្យាបាលបន្ទាន់។',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_payment',
    language: 'km',
    nuanceTags: ['high_urgency'],
    difficulty: 'subtle',
    description: 'Accidental transfer lure requesting refund via gift cards in Khmer.',
  },

  // =========================================================================
  // 4. Fake Jobs
  // =========================================================================
  {
    id: 'SCAM-JOB-EN-001',
    content: 'Hiring Remote Data Specialists! Earn $300-$800 daily by simply rating travel videos on TikTok. Flexible hours, no experience required. Daily deposit required for VIP commission level: https://tiktok-jobs-agency.work/apply',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_job',
    language: 'en',
    nuanceTags: ['unusual_domain'],
    difficulty: 'subtle',
    description: 'Task rating scam with upfront VIP deposit requirement.',
    extractedUrls: ['https://tiktok-jobs-agency.work/apply'],
  },
  {
    id: 'SCAM-JOB-KM-001',
    content: 'ជ្រើសរើសបុគ្គលិកធ្វើការតាមផ្ទះ! គ្រាន់តែចុច Like & Subscribe YouTube រកចំណូលបាន $50 ទៅ $200 ក្នុងមួយថ្ងៃ។ ដាក់ប្រាក់កក់ $30 ដំបូងដើម្បីបើកប្រព័ន្ធការងារ Telegram: @vip_job_task',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_job',
    language: 'km',
    nuanceTags: ['slang_shorthand'],
    difficulty: 'subtle',
    description: 'Khmer task-rating job scam requiring deposit to unlock VIP tasks.',
  },

  // =========================================================================
  // 5. Fake Investments
  // =========================================================================
  {
    id: 'SCAM-INVEST-EN-001',
    content: 'Guaranteed 250% return in 48 hours! Our proprietary AI automated trading bot executes risk-free arbitrage on Bitcoin & USDT. Minimum deposit $100. Withdraw anytime: https://arbitrage-profit-bot.vip',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_investment',
    language: 'en',
    nuanceTags: ['unusual_domain'],
    difficulty: 'obvious',
    description: 'High-yield investment program (HYIP) claiming guaranteed risk-free profit.',
    extractedUrls: ['https://arbitrage-profit-bot.vip'],
  },
  {
    id: 'SCAM-INVEST-MIX-001',
    content: 'ឱកាសវិនិយោគពិសេស! Smart Crypto Trading Bot ធានាចំណេញ 15% daily without risk! ចាប់ផ្តើមត្រឹមតែ $50 ទទួលបានប្រាក់ចំណេញរាល់ថ្ងៃ Telegram @crypto_wealth_advisor',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_investment',
    language: 'km-en',
    nuanceTags: ['mixed_script'],
    difficulty: 'subtle',
    description: 'Mixed Khmer-English guaranteed daily profit crypto investment scheme.',
  },

  // =========================================================================
  // 6. Fake Shopping
  // =========================================================================
  {
    id: 'SCAM-SHOP-EN-001',
    content: 'Amazon Warehouse Overstock Blowout! Brand new Apple MacBook Pro 16" M3 only $49 (95% OFF today only). Limited 12 units remaining due to customs seizure: https://amazon-overstock-clearance.shop/checkout',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_shopping',
    language: 'en',
    nuanceTags: ['high_urgency', 'unusual_domain'],
    difficulty: 'subtle',
    description: 'Too-good-to-be-true 95% discount blowout liquidation scam.',
    extractedUrls: ['https://amazon-overstock-clearance.shop/checkout'],
  },
  {
    id: 'SCAM-SHOP-KM-001',
    content: 'ប្រូម៉ូសិនពិសេសរំលាយស្តុក! iPhone 15 Pro Max តម្លៃត្រឹមតែ $99 ប៉ុណ្ណោះ ព្រោះទំនិញគយរឹបអូស។ កុម្ម៉ង់ឥឡូវនេះមុនអស់ស្តុក https://store-apple-clearance.click/buy',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_shopping',
    language: 'km',
    nuanceTags: ['high_urgency', 'unusual_domain'],
    difficulty: 'subtle',
    description: 'Khmer customs seizure liquidation scam for iPhone at 90% discount.',
    extractedUrls: ['https://store-apple-clearance.click/buy'],
  },

  // =========================================================================
  // 7. Fake Deliveries
  // =========================================================================
  {
    id: 'SCAM-DELIV-EN-001',
    content: 'USPS Notice: Your package #US98421099 has an incomplete address and cannot be delivered. Update street details and pay $1.99 redelivery fee within 12h: https://usps-redelivery-address.online/pay',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_delivery',
    language: 'en',
    nuanceTags: ['high_urgency', 'unusual_domain'],
    difficulty: 'subtle',
    description: 'Postal service incomplete address fee lure.',
    extractedUrls: ['https://usps-redelivery-address.online/pay'],
  },
  {
    id: 'SCAM-DELIV-KM-001',
    content: 'កម្ពុជាប្រៃសណីយ៍ (Cambodia Post): កញ្ចប់ឥវ៉ាន់របស់អ្នកលេខ CP-99214 មិនអាចបញ្ជូនបានដោយសារខ្វះថ្លៃសេវា $2.50។ សូមបង់ប្រាក់ឥឡូវនេះ https://cambodiapost-fee.icu/tracking',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_delivery',
    language: 'km',
    nuanceTags: ['high_urgency', 'unusual_domain'],
    difficulty: 'subtle',
    description: 'Cambodia Post impersonation requiring unpaid redelivery fee.',
    extractedUrls: ['https://cambodiapost-fee.icu/tracking'],
  },

  // =========================================================================
  // 8. Fake Prizes & Giveaways
  // =========================================================================
  {
    id: 'SCAM-PRIZE-EN-001',
    content: 'Congratulations Lucky Winner! Your phone number won the 2026 International Telecom Lottery of $250,000. Send $150 processing stamp duty fee via crypto to release check: https://claim-prize-telecom.site',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_prize',
    language: 'en',
    nuanceTags: ['unusual_domain'],
    difficulty: 'obvious',
    description: 'Advance-fee lottery prize scam asking for processing fee.',
    extractedUrls: ['https://claim-prize-telecom.site'],
  },
  {
    id: 'SCAM-PRIZE-KM-001',
    content: 'អបអរសាទរ! លេខទូរស័ព្ទរបស់អ្នកបានឈ្នះរង្វាន់រថយន្តទំនើប 1 គ្រឿងពីកម្មវិធីផ្សងសំណាង។ សូមផ្ញើប្រាក់ថ្លៃពន្ធដំបូង $100 មកកាន់លេខ 012-998877 ដើម្បីទទួលរង្វាន់។',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_prize',
    language: 'km',
    nuanceTags: [],
    difficulty: 'subtle',
    description: 'Khmer car lottery win asking for advance tax deposit.',
  },

  // =========================================================================
  // 9. Fake Loans
  // =========================================================================
  {
    id: 'SCAM-LOAN-EN-001',
    content: 'Instant Cash Loans up to $50,000! No credit score check, 100% approval rate in 10 minutes. Requires upfront insurance deposit of $300 before fund disbursement. Apply: https://instant-fast-loan.loans/apply',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_loan',
    language: 'en',
    nuanceTags: ['unusual_domain'],
    difficulty: 'subtle',
    description: 'No-credit-check predatory loan scam asking for insurance deposit.',
    extractedUrls: ['https://instant-fast-loan.loans/apply'],
  },
  {
    id: 'SCAM-LOAN-KM-001',
    content: 'សេវាប្រាក់កម្ចីរហ័សទាន់ចិត្ត! អត្រាការប្រាក់ទាបបំផុត 0.5% មិនបាច់មានទ្រព្យបញ្ចាំ មិនឆែក CBC។ អតិថិជនត្រូវបង់ប្រាក់ធានាកម្ចីមុន $50 ដើម្បីបើកប្រាក់កម្ចី $5,000។',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'fake_loan',
    language: 'km',
    nuanceTags: [],
    difficulty: 'subtle',
    description: 'Khmer fast loan requiring advance insurance payment.',
  },

  // =========================================================================
  // 10. Romance Scams
  // =========================================================================
  {
    id: 'SCAM-ROMANCE-EN-001',
    content: 'My dearest darling, my military base in Damascus is under lockdown and my bank account was frozen. My commander says I can fly home to marry you if someone pays my $2,500 emergency transit clearance fee via Bitcoin. Please save me my love!',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'romance_scam',
    language: 'en',
    nuanceTags: ['high_urgency'],
    difficulty: 'subtle',
    description: 'Military doctor / deployed soldier romance scam requesting crypto travel fee.',
  },
  {
    id: 'SCAM-ROMANCE-MIX-001',
    content: 'Hello my sweet heart! I sent a luxury gift package from UK with gold necklace and $50,000 cash for you. But airport customs holding it in Phnom Penh. Please pay $500 clearance fee for delivery na bong.',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'romance_scam',
    language: 'km-en',
    nuanceTags: ['mixed_script', 'slang_shorthand'],
    difficulty: 'adversarial',
    description: 'Overseas lover sending luxury gift box held by customs fee scam.',
  },

  // =========================================================================
  // 11. Impersonation
  // =========================================================================
  {
    id: 'SCAM-IMPER-EN-001',
    content: 'INTERNAL AUDIT NOTICE: This is Richard Davis, Chief Financial Officer. I am currently in a closed-door acquisition meeting and cannot take calls. Wire $42,500 to vendor account immediately for patent filing. Treat this with highest confidentiality.',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'impersonation',
    language: 'en',
    nuanceTags: ['high_urgency'],
    difficulty: 'adversarial',
    description: 'CEO / CFO Business Email Compromise (BEC) wire transfer demand.',
  },
  {
    id: 'SCAM-IMPER-KM-001',
    content: 'ស្នងការដ្ឋាននគរបាលជាតិ៖ ឈ្មោះរបស់អ្នកមានជាប់ពាក់ព័ន្ធនឹងបទល្មើសលាងលុយកខ្វក់។ អ្នកត្រូវតែផ្ទេរប្រាក់ទាំងអស់ក្នុងគណនីមកគណនីត្រួតពិនិត្យរបស់តុលាការជាបន្ទាន់ ដើម្បីបញ្ជាក់ភាពស្អាតស្អំ បើមិនដូច្នេះទេនឹងត្រូវចាប់ខ្លួនក្នុងរយៈពេល 2 ម៉ោង។',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'impersonation',
    language: 'km',
    nuanceTags: ['high_urgency'],
    difficulty: 'subtle',
    description: 'Police & Court money laundering arrest threat coercion in Khmer.',
  },

  // =========================================================================
  // 12. Account Takeover
  // =========================================================================
  {
    id: 'SCAM-ATO-EN-001',
    content: 'CRITICAL SECURITY: A new phone requested a SIM transfer for your mobile number. If you did not authorize this, text "CANCEL 4921" or call +1-800-FAKE-TELCO immediately to stop identity transfer.',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'account_takeover',
    language: 'en',
    nuanceTags: ['high_urgency'],
    difficulty: 'adversarial',
    description: 'SIM swap alert social engineering victim to reveal confirmation codes.',
  },
  {
    id: 'SCAM-ATO-KM-001',
    content: 'ប្រព័ន្ធទូរគមនាគមន៍៖ មានសំណើផ្ទេរលេខទូរស័ព្ទរបស់អ្នកទៅកាន់ទូរស័ព្ទថ្មី។ ដើម្បីបដិសេធ សូមផ្ញើលេខកូដសម្ងាត់ 6 ខ្ទង់ដែលបានផ្ញើមកទូរស័ព្ទរបស់អ្នកមកកាន់យើងខ្ញុំវិញជាបន្ទាន់។',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'account_takeover',
    language: 'km',
    nuanceTags: ['high_urgency'],
    difficulty: 'subtle',
    description: 'Khmer SIM swap cancel alert soliciting 6-digit confirmation code.',
  },

  // =========================================================================
  // 13. OTP Theft
  // =========================================================================
  {
    id: 'SCAM-OTP-EN-001',
    content: 'Google Account Security: We sent a 6-digit verification code to verify your recovery email. Please reply with this OTP code to secure your Gmail from unauthorized access.',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'otp_theft',
    language: 'en',
    nuanceTags: ['high_urgency'],
    difficulty: 'adversarial',
    description: 'Direct SMS reply prompt soliciting Google 2FA verification code.',
  },
  {
    id: 'SCAM-OTP-MIX-001',
    content: 'សួស្តីបង! ខ្ញុំបានច្រឡំបញ្ចូលលេខទូរស័ព្ទបងពេល reset password Telegram. Plz send me the 5-digit code that just arrived on your phone so I can login, thanks bong!',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'otp_theft',
    language: 'km-en',
    nuanceTags: ['mixed_script', 'slang_shorthand'],
    difficulty: 'adversarial',
    description: 'Accidental password reset pretext to steal victim Telegram SMS login code.',
  },

  // =========================================================================
  // 14. Credential Theft
  // =========================================================================
  {
    id: 'SCAM-CRED-EN-001',
    content: 'Meta Portal: Your Instagram business account has violated community guidelines. Provide your current login password and registered email to file appeal: https://instagram-copyright-appeals.com/form',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'credential_theft',
    language: 'en',
    nuanceTags: ['high_urgency'],
    difficulty: 'subtle',
    description: 'Social media copyright violation portal harvesting credentials.',
    extractedUrls: ['https://instagram-copyright-appeals.com/form'],
  },
  {
    id: 'SCAM-CRED-KM-001',
    content: 'ធនាគារកម្ពុជា៖ ដើម្បីរក្សាសុវត្ថិភាពគណនី សូមបញ្ចូលលេខសម្ងាត់កាត ATM (PIN) និងលេខកូដសម្ងាត់ 16 ខ្ទង់របស់អ្នកឡើងវិញតាមរយៈទម្រង់នេះ https://kh-banking-secure.site/pin',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'credential_theft',
    language: 'km',
    nuanceTags: ['unusual_domain'],
    difficulty: 'obvious',
    description: 'Direct solicitation of ATM PIN code in Khmer.',
    extractedUrls: ['https://kh-banking-secure.site/pin'],
  },

  // =========================================================================
  // 15. Malicious Downloads
  // =========================================================================
  {
    id: 'SCAM-DOWN-EN-001',
    content: 'CRITICAL CHROME VULNERABILITY: Your Google Chrome browser is outdated and actively compromised by zero-day exploit CVE-2026-881. Download mandatory emergency patch installer: https://google-chrome-patch-update.com/update_patch.exe',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'malicious_download',
    language: 'en',
    nuanceTags: ['high_urgency'],
    difficulty: 'subtle',
    description: 'Fake emergency browser update delivering executable payload.',
    extractedUrls: ['https://google-chrome-patch-update.com/update_patch.exe'],
  },
  {
    id: 'SCAM-DOWN-KM-001',
    content: 'ឯកសារវិក្កយបត្រពន្ធប្រចាំខែមីនា៖ សូមទាញយកឯកសារវិក្កយបត្រផ្លូវការដើម្បីបង់ពន្ធ https://tax-invoice-cambodia.net/download/tax_invoice.pdf.exe',
    targetType: 'TEXT',
    expectedLabel: 'SCAM',
    category: 'malicious_download',
    language: 'km',
    nuanceTags: ['high_urgency'],
    difficulty: 'adversarial',
    description: 'Double extension executable malware (.pdf.exe) tax lure in Khmer.',
    extractedUrls: ['https://tax-invoice-cambodia.net/download/tax_invoice.pdf.exe'],
  },

  // =========================================================================
  // 16. QR Scams (Quishing)
  // =========================================================================
  {
    id: 'SCAM-QR-EN-001',
    content: 'Scan this QR code to claim your $100 Shell gasoline fuel rebate subsidy courtesy of government stimulus program: https://shell-fuel-rebates.xyz/qr-claim',
    targetType: 'QR',
    expectedLabel: 'SCAM',
    category: 'qr_scam',
    language: 'en',
    nuanceTags: ['unusual_domain'],
    difficulty: 'subtle',
    description: 'Fuel subsidy quishing targeting mobile users.',
    extractedUrls: ['https://shell-fuel-rebates.xyz/qr-claim'],
  },
  {
    id: 'SCAM-QR-KM-001',
    content: 'ស្កេន KHQR ដើម្បីទទួលបានប្រាក់ឧបត្ថម្ភពិសេស $50 ពីរាជរដ្ឋាភិបាល https://khqr-government-bonus.info/claim',
    targetType: 'QR',
    expectedLabel: 'SCAM',
    category: 'qr_scam',
    language: 'km',
    nuanceTags: ['unusual_domain'],
    difficulty: 'subtle',
    description: 'Fake KHQR stimulus bonus claim lure.',
    extractedUrls: ['https://khqr-government-bonus.info/claim'],
  },
];
