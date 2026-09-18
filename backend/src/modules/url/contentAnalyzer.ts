/**
 * Pinit Website Content Signal Analyzer
 * Inspects safe HTML snippets captured during network probing:
 * - Detects page title brand impersonation (e.g. title says 'PayPal' on attacker.com)
 * - Identifies credential/password input forms on unverified third-party hosts
 * - Identifies credit card input fields
 * - Detects meta-refresh sneaked redirects
 */

import { TARGET_BRANDS, isLegitimateBrandDomain } from './brandDetector';
import { ContentSignals } from './types';

export class ContentAnalyzer {
  /**
   * Analyzes an HTML snippet fetched safely from a probed URL.
   */
  analyze(htmlSnippet: string, hostname: string, isWhitelisted = false): ContentSignals {
    if (!htmlSnippet || htmlSnippet.trim().length === 0) {
      return { evaluated: false };
    }

    const lowerHtml = htmlSnippet.toLowerCase();

    // 1. Title Extraction
    let pageTitle: string | undefined;
    const titleMatch = htmlSnippet.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    if (titleMatch) {
      pageTitle = titleMatch[1].trim().replace(/\s+/g, ' ');
    }

    // 2. Title Brand Mismatch Check
    let titleBrandMismatch = false;
    let matchedBrandInTitle: string | undefined;

    if (pageTitle && !isWhitelisted) {
      const lowerTitle = pageTitle.toLowerCase();
      for (const brand of TARGET_BRANDS) {
        // If title contains brand name
        if (
          lowerTitle.includes(brand.name.toLowerCase()) ||
          lowerTitle.includes(brand.key)
        ) {
          // Check if hostname is legitimate for this brand
          if (!isLegitimateBrandDomain(hostname, brand)) {
            titleBrandMismatch = true;
            matchedBrandInTitle = brand.name;
            break;
          }
        }
      }
    }

    // 3. Password / Login Form Detection
    const hasPasswordInput =
      /<input[^>]+type=['"]password['"]/i.test(htmlSnippet) ||
      /type=['"]password['"]/i.test(htmlSnippet);

    const hasLoginForm =
      hasPasswordInput ||
      /<form[^>]+(?:action|id|name)=['"][^'"]*(?:login|signin|auth|session)[^'"]*['"]/i.test(htmlSnippet);

    // 4. Credit Card Input Detection
    const hasCreditCardInput =
      /(?:name|id|autocomplete)=['"][^'"]*(?:cc-number|cardnumber|creditcard|cvv|cvc|exp-date)[^'"]*['"]/i.test(
        lowerHtml
      );

    // 5. Meta-Refresh Sneak Redirect
    let hasMetaRefresh = false;
    let metaRefreshTarget: string | undefined;
    const metaRefreshMatch = htmlSnippet.match(
      /<meta[^>]+http-equiv=['"]refresh['"][^>]+content=['"]\d+;\s*url=([^'"]+)['"]/i
    );
    if (metaRefreshMatch) {
      hasMetaRefresh = true;
      metaRefreshTarget = metaRefreshMatch[1].trim();
    }

    const isSuspiciousLoginDrop =
      (hasPasswordInput || hasCreditCardInput || titleBrandMismatch) && !isWhitelisted;

    return {
      evaluated: true,
      pageTitle,
      titleBrandMismatch,
      matchedBrandInTitle,
      hasLoginForm,
      hasPasswordInput,
      hasCreditCardInput,
      hasMetaRefresh,
      metaRefreshTarget,
      isSuspiciousLoginDrop,
    };
  }
}

export const contentAnalyzer = new ContentAnalyzer();
