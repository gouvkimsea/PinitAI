import { EvaluationSample } from './types';

export const LEGITIMATE_SAMPLES: EvaluationSample[] = [
  // =========================================================================
  // 1. Bank Messages (Authentic)
  // =========================================================================
  {
    id: 'LEGIT-BANK-EN-001',
    content: 'ABA Bank Alert: Your account was debited $14.50 at STARBUCKS BKK1 on 18-MAR-2026. Available balance: $1,280.45. For inquiries, call official hotline 023 225 333.',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'bank_message',
    language: 'en',
    nuanceTags: ['informational', 'polite_neutral'],
    difficulty: 'subtle',
    description: 'Standard authentic debit card purchase notification with balance.',
  },
  {
    id: 'LEGIT-BANK-KM-001',
    content: 'ធនាគារ អេស៊ីលីដា ភីអិលស៊ី៖ លោកអ្នកបានទទួលប្រាក់ចំនួន 200,000 រៀល ពីគណនីលេខ *******8812។ សមតុល្យគណនីបច្ចុប្បន្នគឺ 1,450,000 រៀល។ សូមអរគុណដែលបានប្រើប្រាស់សេវា ACLEDA Mobile។',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'bank_message',
    language: 'km',
    nuanceTags: ['informational', 'polite_neutral'],
    difficulty: 'subtle',
    description: 'Authentic Khmer bank deposit receipt notification without links.',
  },
  {
    id: 'LEGIT-BANK-OTP-001',
    content: 'Your Wing Bank verification code is 491024. Valid for 5 minutes. DO NOT SHARE this code with anyone, including Wing staff. We will never call to ask for your OTP.',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'bank_message',
    language: 'en',
    nuanceTags: ['high_urgency'],
    difficulty: 'adversarial',
    description: 'Authentic OTP dispatch message containing security warning never to share.',
  },

  // =========================================================================
  // 2. Delivery Messages (Authentic)
  // =========================================================================
  {
    id: 'LEGIT-DELIV-EN-001',
    content: 'DHL Express: Shipment #8492019482 is out for delivery today with courier Sovann. No payment required. Track delivery status live: https://www.dhl.com/en/express/tracking.html?tracking-id=8492019482&brand=DHL_GLOBAL_FORWARDING&locale=en_KH&source=mobile_sms_dispatch_automated_gateway',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'delivery_message',
    language: 'en',
    nuanceTags: ['long_url'],
    difficulty: 'subtle',
    description: 'Authentic DHL delivery notification with very long tracking URL on authentic domain.',
    extractedUrls: ['https://www.dhl.com/en/express/tracking.html?tracking-id=8492019482&brand=DHL_GLOBAL_FORWARDING&locale=en_KH&source=mobile_sms_dispatch_automated_gateway'],
  },
  {
    id: 'LEGIT-DELIV-KM-001',
    content: 'សួស្តីបង! ខ្ញុំអ្នកដឹកជញ្ជូន J&T Express ឥវ៉ាន់បងបានមកដល់ហើយ ខ្ញុំនៅមុខផ្ទះបង។ តើបងនៅផ្ទះទេបាទ?',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'delivery_message',
    language: 'km',
    nuanceTags: ['polite_neutral'],
    difficulty: 'subtle',
    description: 'Direct courier arrival message in Khmer.',
  },
  {
    id: 'LEGIT-DELIV-SHORT-001',
    content: 'Cambodia Post: Your parcel has arrived at Post Office Central. View collection hours: https://cambodiapost.post/tracking/CP882',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'delivery_message',
    language: 'en',
    nuanceTags: ['unusual_domain'],
    difficulty: 'subtle',
    description: 'Authentic Cambodia Post arrival using unusual official .post TLD.',
    extractedUrls: ['https://cambodiapost.post/tracking/CP882'],
  },

  // =========================================================================
  // 3. Job Advertisements (Authentic)
  // =========================================================================
  {
    id: 'LEGIT-JOB-EN-001',
    content: 'We are hiring: Senior Full-Stack Engineer (React / Node.js) at Smart Axiata. Salary $1,800 - $2,800/mo. Full healthcare, annual bonus. Send resume to careers@smart.com.kh or apply on LinkedIn: https://www.linkedin.com/jobs/view/39201948',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'job_advertisement',
    language: 'en',
    nuanceTags: ['unusual_domain'],
    difficulty: 'subtle',
    description: 'Authentic technical job listing with realistic compensation and company email.',
    extractedUrls: ['https://www.linkedin.com/jobs/view/39201948'],
  },
  {
    id: 'LEGIT-JOB-KM-001',
    content: 'ក្រុមហ៊ុន ជីប ម៉ុង ត្រូវការជ្រើសរើសបុគ្គលិកផ្នែកលក់ (Sales Executive) ចំនួន 2 នាក់។ ប្រាក់ខែសមរម្យ បូកថ្លៃកុម្មុយស្យុង។ បេក្ខជនចាប់អារម្មណ៍អាចផ្ញើ CV មកកាន់ recruitment@chipmong.com ឬទាក់ទង 012 888 999។',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'job_advertisement',
    language: 'km',
    nuanceTags: ['polite_neutral'],
    difficulty: 'subtle',
    description: 'Authentic Khmer company recruitment post without deposits or hype.',
  },

  // =========================================================================
  // 4. Shopping Websites & Order Confirmations (Authentic)
  // =========================================================================
  {
    id: 'LEGIT-SHOP-EN-001',
    content: 'Thank you for shopping at Apple Store! Your order #W991824701 for AirPods Pro has been confirmed and is preparing to ship. View receipt: https://www.apple.com/shop/order/status/W991824701',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'shopping_website',
    language: 'en',
    nuanceTags: ['polite_neutral'],
    difficulty: 'subtle',
    description: 'Official Apple Store purchase receipt on apple.com.',
    extractedUrls: ['https://www.apple.com/shop/order/status/W991824701'],
  },
  {
    id: 'LEGIT-SHOP-KM-001',
    content: 'ហាងសៀវភៅបណ្ណាគារសន្តិភាព៖ ការកុម្ម៉ង់សៀវភៅលេខ #BK-8891 ទទួលបានជោគជ័យ។ ឥវ៉ាន់នឹងដឹកជូននៅថ្ងៃស្អែក។ សូមអរគុណ!',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'shopping_website',
    language: 'km',
    nuanceTags: ['polite_neutral'],
    difficulty: 'subtle',
    description: 'Authentic bookstore purchase confirmation in Khmer.',
  },

  // =========================================================================
  // 5. Payment Instructions (Authentic)
  // =========================================================================
  {
    id: 'LEGIT-PAY-EN-001',
    content: 'Invoice #INV-2026-042 for cloud consulting services has been generated. Due date: April 5, 2026. Total: $450.00. Payment methods: ABA PayWay or Bakong KHQR available on client portal: https://portal.acme-consulting.com/invoices/INV-2026-042',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'payment_instructions',
    language: 'en',
    nuanceTags: ['informational'],
    difficulty: 'subtle',
    description: 'Professional B2B service invoice with standard payment terms.',
    extractedUrls: ['https://portal.acme-consulting.com/invoices/INV-2026-042'],
  },
  {
    id: 'LEGIT-PAY-MIX-001',
    content: 'Here is our Bakong KHQR payment link for the workshop fee ($15). You can scan using any banking app in Cambodia: https://khqr.bakong.nbc.org.kh/pay?merchant=digital_academy_kh&amount=15',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'payment_instructions',
    language: 'km-en',
    nuanceTags: ['unusual_domain'],
    difficulty: 'subtle',
    description: 'Authentic National Bank of Cambodia Bakong KHQR payment link on .org.kh.',
    extractedUrls: ['https://khqr.bakong.nbc.org.kh/pay?merchant=digital_academy_kh&amount=15'],
  },

  // =========================================================================
  // 6. Customer Support Messages (Authentic)
  // =========================================================================
  {
    id: 'LEGIT-SUPP-EN-001',
    content: 'Hi Alex, regarding your ticket #8942: We have updated your billing address as requested. No further action is required from your side. Have a wonderful weekend! Best, Emma from Stripe Support.',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'customer_support',
    language: 'en',
    nuanceTags: ['polite_neutral'],
    difficulty: 'subtle',
    description: 'Authentic helpdesk customer ticket resolution message without requests.',
  },
  {
    id: 'LEGIT-SUPP-KM-001',
    content: 'សួស្តីបង! ក្រុមការងារបច្ចេកទេសបានដោះស្រាយបញ្ហាប្រព័ន្ធអ៊ីនធឺណិតជូនបងរួចរាល់ហើយ។ ប្រសិនបើបងនៅតែជួបបញ្ហា សូមទាក់ទងមកកាន់លេខ 023 999 111 វិញបានគ្រប់ពេលវេលា។',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'customer_support',
    language: 'km',
    nuanceTags: ['polite_neutral'],
    difficulty: 'subtle',
    description: 'Khmer ISP customer support resolution message.',
  },

  // =========================================================================
  // 7. Government Announcements (Authentic)
  // =========================================================================
  {
    id: 'LEGIT-GOV-EN-001',
    content: 'General Department of Taxation (GDT): Annual Tax on Income (TOI) filing deadline for fiscal year 2025 is March 31, 2026. Submit e-filing directly via official GDT portal: https://tax.gov.kh/en/e-services',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'government_announcement',
    language: 'en',
    nuanceTags: ['unusual_domain', 'informational'],
    difficulty: 'subtle',
    description: 'Official tax filing deadline announcement on authentic .gov.kh domain.',
    extractedUrls: ['https://tax.gov.kh/en/e-services'],
  },
  {
    id: 'LEGIT-GOV-KM-001',
    content: 'ក្រសួងអប់រំ យុវជន និងកីឡា (MoEYS)៖ សេចក្ដីជូនដំណឹងស្ដីពីកាលបរិច្ឆេទប្រឡងសញ្ញាបត្រមធ្យមសិក្សាទុតិយភូមិ (បាក់ឌុប) សម្រាប់ឆ្នាំសិក្សា ២០២៥-២០២៦។ ព័ត៌មានលម្អិតសូមមើលគេហទំព័រផ្លូវការ http://www.moeys.gov.kh',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'government_announcement',
    language: 'km',
    nuanceTags: ['unusual_domain', 'informational'],
    difficulty: 'subtle',
    description: 'Official education ministry exam announcement on official .gov.kh.',
    extractedUrls: ['http://www.moeys.gov.kh'],
  },

  // =========================================================================
  // 8. Promotional Messages (Authentic)
  // =========================================================================
  {
    id: 'LEGIT-PROMO-EN-001',
    content: 'Smart Axiata: Recharge $2 today and get 20GB extra high-speed data valid for 7 days! Dial *888*20# or recharge easily on SmartNas app. Terms & conditions apply.',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'promotional_message',
    language: 'en',
    nuanceTags: ['informational'],
    difficulty: 'subtle',
    description: 'Standard carrier mobile data recharge promotion with USSD dial string.',
  },
  {
    id: 'LEGIT-PROMO-KM-001',
    content: 'ប្រូម៉ូសិនពិសេសពី Cellcard! ចាក់លុយចាប់ពី $1 ឡើងទៅ នឹងទទួលបានការបង្វិលកងសំណាងឈ្នះទិន្នន័យអ៊ីនធឺណិតរហូតដល់ 10GB។ ចុច *123# ដើម្បីពិនិត្យសមតុល្យ។',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'promotional_message',
    language: 'km',
    nuanceTags: ['informational'],
    difficulty: 'subtle',
    description: 'Authentic telecom promotion with USSD dial string in Khmer.',
  },

  // =========================================================================
  // 9. Investment Information & Market Research (Authentic)
  // =========================================================================
  {
    id: 'LEGIT-INVEST-EN-001',
    content: 'Cambodia Securities Exchange (CSX) Market Recap: CSX Index closed at 468.21 points (+0.35%). Total trading volume recorded 142,580 shares. Full daily trading summary available on CSX official bulletin: https://csx.com.kh/market/daily_summary',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'investment_information',
    language: 'en',
    nuanceTags: ['unusual_domain', 'informational'],
    difficulty: 'subtle',
    description: 'Educational financial market close report on legitimate csx.com.kh domain.',
    extractedUrls: ['https://csx.com.kh/market/daily_summary'],
  },
  {
    id: 'LEGIT-INVEST-KM-001',
    content: 'សេចក្ដីព្រាងរបាយការណ៍សេដ្ឋកិច្ចប្រចាំត្រីមាស៖ កំណើនសេដ្ឋកិច្ចកម្ពុជាត្រូវបានព្យាករថានឹងសម្រេចបាន 6.1% ក្នុងឆ្នាំ 2026 ដោយសារកំណើនវិស័យកាត់ដេរ និងទេសចរណ៍។ ព័ត៌មានលម្អិតពីធនាគារជាតិនៃកម្ពុជា https://www.nbc.gov.kh/economic_report.php',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'investment_information',
    language: 'km',
    nuanceTags: ['unusual_domain', 'informational'],
    difficulty: 'subtle',
    description: 'Authentic quarterly central bank economic research report.',
    extractedUrls: ['https://www.nbc.gov.kh/economic_report.php'],
  },

  // =========================================================================
  // 10. Social Media & Personal Messages (Authentic with Slang/Misspellings)
  // =========================================================================
  {
    id: 'LEGIT-SOCIAL-EN-001',
    content: 'Hey bro, are u free for dinner tonite? Me and Sarah r thinking about hitting that new pizza place near Russian Market at 7pm lol. Lmk!',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'social_media_message',
    language: 'en',
    nuanceTags: ['slang_shorthand', 'misspellings'],
    difficulty: 'adversarial',
    description: 'Informal friendly social message with slang ("u", "tonite", "r", "lol", "lmk").',
  },
  {
    id: 'LEGIT-SOCIAL-KM-001',
    content: 'សួស្តីម៉ាក់! កូនទើបចេញពីរៀនម៉ោង 5 នេះ ឥឡូវកំពុងជិះម៉ូតូទៅផ្ទះវិញហើយម៉ាក់។ យប់នេះមានម្ហូបអីញ៉ាំដែរម៉ាក់?',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'social_media_message',
    language: 'km',
    nuanceTags: ['polite_neutral'],
    difficulty: 'subtle',
    description: 'Personal family conversation in Khmer heading home from school.',
  },
  {
    id: 'LEGIT-SOCIAL-SHORT-001',
    content: 'Guys, here is the agenda for our research paper sprint next Monday: https://tinyurl.com/meeting-agenda-notes . Plz review section 2 before we meet!',
    targetType: 'TEXT',
    expectedLabel: 'LEGITIMATE',
    category: 'social_media_message',
    language: 'en',
    nuanceTags: ['legitimate_shortener', 'slang_shorthand'],
    difficulty: 'adversarial',
    description: 'Legitimate TinyURL link sharing meeting notes with friends.',
    extractedUrls: ['https://tinyurl.com/meeting-agenda-notes'],
  },
];
