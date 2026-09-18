import axios, { AxiosResponse } from 'axios';
import { validateUrlForSsrf } from '../../scanners/url/ssrfGuard';
import { NetworkProbeResult, TlsInfo } from './types';
import { logger } from '../../utils/logger';
import { LruCache } from '../../utils/lruCache';
import { contentAnalyzer } from './contentAnalyzer';
import { httpAgent, httpsAgent } from '../../utils/httpConnectionPool';

const MAX_REDIRECT_HOPS = 5;
const PROBE_TIMEOUT_MS = 2500;
const MAX_TOTAL_PROBE_TIMEOUT_MS = 6000;

export const probeCache = new LruCache<string, NetworkProbeResult>({
  maxSize: 1000,
  defaultTtlMs: 10 * 60 * 1000, // 10 minutes TTL
});

/**
 * Extracts TLS certificate details from an active HTTPS socket if available.
 */
function extractTlsDetails(res: AxiosResponse): TlsInfo | undefined {
  const isHttps = res.config.url?.startsWith('https:') ?? false;
  if (!isHttps) {
    return { isHttps: false };
  }

  try {
    const socket = res.request?.res?.socket || res.request?.socket;
    if (socket && typeof socket.getPeerCertificate === 'function') {
      const cert = socket.getPeerCertificate(true);
      if (cert && Object.keys(cert).length > 0) {
        const issuer = cert.issuer?.O || cert.issuer?.CN || (typeof cert.issuer === 'string' ? cert.issuer : undefined);
        const validFrom = cert.valid_from;
        const validTo = cert.valid_to;
        const isSelfSigned = Boolean(
          cert.issuer &&
          cert.subject &&
          cert.issuer.CN === cert.subject.CN &&
          (cert.issuer.O === cert.subject.O || !cert.issuer.O)
        );
        const isExpired = validTo ? new Date(validTo).getTime() < Date.now() : false;
        const daysUntilExpiration = validTo
          ? Math.floor((new Date(validTo).getTime() - Date.now()) / (1000 * 60 * 60 * 24))
          : undefined;

        return {
          isHttps: true,
          protocol: socket.getProtocol ? socket.getProtocol() : 'TLS',
          issuer,
          validFrom,
          validTo,
          isSelfSigned,
          isExpired,
          daysUntilExpiration,
        };
      }
    }
    return { isHttps: true };
  } catch {
    return { isHttps: true };
  }
}

/**
 * Performs safe, isolated network probing of a URL.
 * Enforces pre-flight SSRF checks on every hop, records redirect chains,
 * detects cross-domain redirects, extracts TLS certificates, and inspects page content.
 */
export async function probeUrlSafely(targetUrl: string): Promise<NetworkProbeResult> {
  const cached = probeCache.get(targetUrl);
  if (cached) {
    return { ...cached, latencyMs: 0 };
  }

  const redirectChain: string[] = [targetUrl];
  let currentUrl = targetUrl;
  let finalStatusCode: number | undefined;
  let hasRedirects = false;
  let redirectCount = 0;
  let resolvedIp: string | undefined;
  let bodySnippet: string | undefined;
  let tlsInfo: TlsInfo | undefined;
  const startTime = Date.now();

  try {
    const parsedInitial = new URL(targetUrl);
    const initialDomain = parsedInitial.hostname.toLowerCase();

    // 1. Initial SSRF Pre-flight Check
    const initialSsrf = await validateUrlForSsrf(targetUrl);
    resolvedIp = initialSsrf.resolvedIp;

    if (!initialSsrf.isSafe) {
      logger.trackSuspiciousActivity({
        activityType: 'SSRF_ATTEMPT',
        severity: 'CRITICAL',
        details: {
          url: targetUrl,
          reason: initialSsrf.blockedReason,
          resolvedIp: initialSsrf.resolvedIp,
        },
      });

      logger.warn('SSRF hazard blocked on initial URL probe', {
        url: targetUrl,
        reason: initialSsrf.blockedReason,
      });

      return {
        probed: false,
        hasRedirects: false,
        redirectCount: 0,
        redirectChain: [targetUrl],
        crossDomainRedirect: false,
        targetDomainChanged: false,
        ssrfSafe: false,
        ssrfBlockedReason: initialSsrf.blockedReason,
        resolvedIp: initialSsrf.resolvedIp,
        latencyMs: Date.now() - startTime,
        errorMessage: initialSsrf.blockedReason,
      };
    }

    // 2. Hop-by-hop HTTP probing with strict redirect boundary enforcement
    for (let hop = 0; hop < MAX_REDIRECT_HOPS; hop++) {
      if (Date.now() - startTime > MAX_TOTAL_PROBE_TIMEOUT_MS) {
        logger.debug('Reached maximum total probe timeout window', { targetUrl });
        break;
      }

      let response: AxiosResponse;

      try {
        response = await axios.get(currentUrl, {
          httpAgent,
          httpsAgent,
          timeout: PROBE_TIMEOUT_MS,
          maxRedirects: 0, // Never allow Axios to follow redirects automatically without SSRF checks
          maxBodyLength: 512 * 1024, // 512 KB response body ceiling to prevent DoS/memory exhaustion
          maxContentLength: 512 * 1024,
          validateStatus: () => true, // Accept any HTTP status code
          transformResponse: [(data) => data], // Keep raw string without automatic JSON parse
          headers: {
            'User-Agent': 'PinIt-Security-Scanner/1.0 (+https://pinit.security/bot)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          },
        });
      } catch (err: any) {
        logger.debug('Network probe request encountered network or timeout error', {
          url: currentUrl,
          error: (err as Error).message,
        });
        return {
          probed: true,
          statusCode: finalStatusCode,
          hasRedirects,
          redirectCount,
          redirectChain,
          finalDestinationUrl: currentUrl,
          crossDomainRedirect: checkCrossDomain(initialDomain, currentUrl),
          targetDomainChanged: initialDomain !== extractHost(currentUrl),
          ssrfSafe: true,
          resolvedIp,
          latencyMs: Date.now() - startTime,
          errorMessage: (err as Error).message,
        };
      }

      finalStatusCode = response.status;
      tlsInfo = extractTlsDetails(response);

      // Check for redirect response (301, 302, 303, 307, 308)
      if ([301, 302, 303, 307, 308].includes(response.status) && response.headers.location) {
        let redirectTarget: string;
        try {
          redirectTarget = new URL(response.headers.location, currentUrl).toString();
        } catch {
          logger.debug('Invalid redirect Location header encountered', {
            location: response.headers.location,
            base: currentUrl,
          });
          break;
        }

        hasRedirects = true;
        redirectCount++;
        redirectChain.push(redirectTarget);

        // SSRF check on the redirect destination BEFORE following the next hop
        const hopSsrf = await validateUrlForSsrf(redirectTarget);
        if (!hopSsrf.isSafe) {
          logger.warn('SSRF hazard blocked on redirect hop', {
            target: redirectTarget,
            reason: hopSsrf.blockedReason,
          });

          return {
            probed: true,
            statusCode: finalStatusCode,
            hasRedirects: true,
            redirectCount,
            redirectChain,
            finalDestinationUrl: redirectTarget,
            crossDomainRedirect: true,
            targetDomainChanged: true,
            ssrfSafe: false,
            ssrfBlockedReason: hopSsrf.blockedReason,
            resolvedIp: hopSsrf.resolvedIp,
            latencyMs: Date.now() - startTime,
            errorMessage: hopSsrf.blockedReason,
          };
        }

        currentUrl = redirectTarget;
      } else {
        // Terminal HTTP response reached - validate Content-Type and capture body snippet
        const contentType = String(response.headers['content-type'] || '').toLowerCase();
        const isHtmlOrText =
          contentType.includes('text/html') ||
          contentType.includes('text/plain') ||
          contentType.includes('application/xhtml+xml') ||
          !contentType; // some minimal servers omit content-type

        if (isHtmlOrText && typeof response.data === 'string') {
          bodySnippet = response.data.slice(0, 32768);
        }
        break;
      }
    }

    const finalHost = extractHost(currentUrl);
    const crossDomain = checkCrossDomain(initialDomain, currentUrl);

    // Run content analysis on HTML body snippet if captured
    const contentSignals = bodySnippet
      ? contentAnalyzer.analyze(bodySnippet, finalHost)
      : undefined;

    const finalResult: NetworkProbeResult = {
      probed: true,
      statusCode: finalStatusCode,
      hasRedirects,
      redirectCount,
      redirectChain,
      finalDestinationUrl: currentUrl,
      crossDomainRedirect: crossDomain,
      targetDomainChanged: initialDomain !== finalHost,
      ssrfSafe: true,
      resolvedIp,
      latencyMs: Date.now() - startTime,
      bodySnippet,
      tlsInfo,
      contentSignals,
    };

    probeCache.set(targetUrl, finalResult);
    return finalResult;
  } catch (err: any) {
    logger.debug('Unexpected failure in probeUrlSafely', { url: targetUrl, error: (err as Error).message });
    return {
      probed: false,
      hasRedirects,
      redirectCount,
      redirectChain,
      finalDestinationUrl: currentUrl,
      crossDomainRedirect: false,
      targetDomainChanged: false,
      ssrfSafe: true,
      resolvedIp,
      latencyMs: Date.now() - startTime,
      errorMessage: (err as Error).message,
    };
  }
}

function extractHost(urlString: string): string {
  try {
    return new URL(urlString).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function checkCrossDomain(initialHost: string, targetUrl: string): boolean {
  try {
    const targetHost = new URL(targetUrl).hostname.toLowerCase();
    if (initialHost === targetHost) return false;
    // Check if subdomains of the same root domain
    const initialParts = initialHost.split('.');
    const targetParts = targetHost.split('.');
    const initialBase = initialParts.slice(-2).join('.');
    const targetBase = targetParts.slice(-2).join('.');
    return initialBase !== targetBase;
  } catch {
    return false;
  }
}
