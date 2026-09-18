/**
 * Pinit URL Detection Benchmark & Metrics Evaluator
 * Measures detection accuracy, precision, recall, false positive rate (FPR),
 * and false negative rate (FNR) against curated legitimate and malicious datasets.
 */

import { urlIntelligence } from './urlIntelligence';

export interface BenchmarkSample {
  url: string;
  expectedLabel: 'legitimate' | 'malicious';
  category: string;
}

export interface BenchmarkResult {
  total: number;
  truePositives: number;
  trueNegatives: number;
  falsePositives: number;
  falseNegatives: number;
  accuracy: number;
  precision: number;
  recall: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  details: Array<{
    url: string;
    expected: string;
    predictedSeverity: string;
    score: number;
    isCorrect: boolean;
  }>;
}

export const BENCHMARK_DATASET: BenchmarkSample[] = [
  // --- Legitimate Websites (Expected: Safe / Low Risk / Whitelisted) ---
  { url: 'https://www.google.com', expectedLabel: 'legitimate', category: 'search' },
  { url: 'https://github.com/torvalds/linux', expectedLabel: 'legitimate', category: 'developer' },
  { url: 'https://en.wikipedia.org/wiki/Computer_security', expectedLabel: 'legitimate', category: 'reference' },
  { url: 'https://www.microsoft.com/en-us/software-download/windows11', expectedLabel: 'legitimate', category: 'tech_download' },
  { url: 'https://apple.com/iphone', expectedLabel: 'legitimate', category: 'ecommerce' },
  { url: 'https://www.paypal.com/signin', expectedLabel: 'legitimate', category: 'authentic_banking_login' },
  { url: 'https://www.ababank.com/personal-banking/', expectedLabel: 'legitimate', category: 'authentic_cambodian_bank' },
  { url: 'https://www.acledabank.com.kh/kh/eng/', expectedLabel: 'legitimate', category: 'authentic_cambodian_bank' },
  { url: 'https://wingmoney.com/en/personal/', expectedLabel: 'legitimate', category: 'authentic_cambodian_fintech' },
  { url: 'https://tax.gov.kh/en/', expectedLabel: 'legitimate', category: 'authentic_cambodian_govt' },
  { url: 'https://cambodiapost.post/', expectedLabel: 'legitimate', category: 'authentic_cambodian_post' },
  { url: 'https://dhl.com/en/express.html', expectedLabel: 'legitimate', category: 'authentic_shipping' },
  { url: 'https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array', expectedLabel: 'legitimate', category: 'developer_forum' },
  { url: 'http://johndoe-travelblog.com', expectedLabel: 'legitimate', category: 'plain_http_benign_blog' },
  { url: 'https://tinyurl.com/meeting-agenda-notes', expectedLabel: 'legitimate', category: 'benign_shortener' },

  // --- Malicious / Deceptive Samples (Expected: High Risk / Critical) ---
  { url: 'https://paypa1.com/signin', expectedLabel: 'malicious', category: 'typosquatting_paypal' },
  { url: 'https://paypai.com/account/login', expectedLabel: 'malicious', category: 'lookalike_paypal_capital_i' },
  { url: 'https://paypal-security-verification.com/login', expectedLabel: 'malicious', category: 'combisquatting_paypal' },
  { url: 'https://paypal.com.verify-user.attacker.xyz/login', expectedLabel: 'malicious', category: 'subdomain_spoof_paypal' },
  { url: 'https://ababank-verify.com/portal/login', expectedLabel: 'malicious', category: 'fake_cambodian_bank_aba' },
  { url: 'https://wing-security-update.xyz/login', expectedLabel: 'malicious', category: 'fake_cambodian_bank_wing' },
  { url: 'https://acledabank-online.net/auth', expectedLabel: 'malicious', category: 'fake_cambodian_bank_acleda' },
  { url: 'https://canadiabank-verify.site/signin', expectedLabel: 'malicious', category: 'fake_cambodian_bank_canadia' },
  { url: 'https://cambodiapost-fee-tracking.com/pay', expectedLabel: 'malicious', category: 'fake_cambodian_delivery' },
  { url: 'https://dhl-parcel-delivery.xyz/tracking/redelivery', expectedLabel: 'malicious', category: 'fake_shipping_dhl' },
  { url: 'https://fedex-package-update.online/pay-fee', expectedLabel: 'malicious', category: 'fake_shipping_fedex' },
  { url: 'https://accounts-google-security.tk/login', expectedLabel: 'malicious', category: 'fake_login_google' },
  { url: 'https://fileshare-portal.com/invoices/payment_slip.exe', expectedLabel: 'malicious', category: 'malware_executable_download' },
  { url: 'http://45.33.32.156/portal/login', expectedLabel: 'malicious', category: 'ip_address_host' },
  { url: 'https://google.com@evil-attacker.com/login', expectedLabel: 'malicious', category: 'userinfo_redirection_trick' },
  { url: 'https://login-service.com?redirect=https://evil-phishing.com/steal', expectedLabel: 'malicious', category: 'open_redirect' },
  { url: 'https://arnazon.com/ap/signin', expectedLabel: 'malicious', category: 'lookalike_amazon_rn' },
  { url: 'https://vvhatsapp-web.online/login', expectedLabel: 'malicious', category: 'lookalike_whatsapp_vv' },
];

export class UrlBenchmarkEvaluator {
  async runBenchmark(dataset = BENCHMARK_DATASET): Promise<BenchmarkResult> {
    let truePositives = 0;
    let trueNegatives = 0;
    let falsePositives = 0;
    let falseNegatives = 0;

    const details: BenchmarkResult['details'] = [];

    for (const sample of dataset) {
      const res = await urlIntelligence.analyze(sample.url, { skipNetworkProbe: true });

      // Malicious threshold: compositeScore >= 40 (medium, high, critical)
      const isPredictedMalicious = res.compositeScore >= 40;

      let isCorrect = false;
      if (sample.expectedLabel === 'malicious') {
        if (isPredictedMalicious) {
          truePositives++;
          isCorrect = true;
        } else {
          falseNegatives++;
        }
      } else {
        if (!isPredictedMalicious) {
          trueNegatives++;
          isCorrect = true;
        } else {
          falsePositives++;
        }
      }

      details.push({
        url: sample.url,
        expected: sample.expectedLabel,
        predictedSeverity: res.severity,
        score: res.compositeScore,
        isCorrect,
      });
    }

    const total = dataset.length;
    const accuracy = Math.round(((truePositives + trueNegatives) / total) * 1000) / 10;
    const precision =
      truePositives + falsePositives > 0
        ? Math.round((truePositives / (truePositives + falsePositives)) * 1000) / 10
        : 100;
    const recall =
      truePositives + falseNegatives > 0
        ? Math.round((truePositives / (truePositives + falseNegatives)) * 1000) / 10
        : 100;

    const actualNegatives = trueNegatives + falsePositives;
    const falsePositiveRate =
      actualNegatives > 0 ? Math.round((falsePositives / actualNegatives) * 1000) / 10 : 0;

    const actualPositives = truePositives + falseNegatives;
    const falseNegativeRate =
      actualPositives > 0 ? Math.round((falseNegatives / actualPositives) * 1000) / 10 : 0;

    return {
      total,
      truePositives,
      trueNegatives,
      falsePositives,
      falseNegatives,
      accuracy,
      precision,
      recall,
      falsePositiveRate,
      falseNegativeRate,
      details,
    };
  }
}

export const urlBenchmarkEvaluator = new UrlBenchmarkEvaluator();
