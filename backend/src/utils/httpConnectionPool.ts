import http from 'http';
import https from 'https';
import axios, { AxiosInstance } from 'axios';

/**
 * High-Performance HTTP/HTTPS Connection Pooling
 *
 * Reuses TCP connections across outgoing HTTP requests to minimize TCP/TLS handshake latency,
 * prevent socket exhaustion, and optimize outbound throughput.
 */
export const httpAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 50,
  maxFreeSockets: 10,
  timeout: 5000,
});

export const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 50,
  maxFreeSockets: 10,
  timeout: 5000,
});

/**
 * Pre-configured Axios instance using connection pooling agents
 */
export const pooledAxios: AxiosInstance = axios.create({
  httpAgent,
  httpsAgent,
  timeout: 5000,
  headers: {
    'Connection': 'keep-alive',
    'User-Agent': 'PinIt-Security-Engine/2.1',
  },
});
