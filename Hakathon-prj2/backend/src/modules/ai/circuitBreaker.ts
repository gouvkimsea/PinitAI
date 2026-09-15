import { logger } from '../../utils/logger';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerOptions {
  name: string;
  failureThreshold?: number;
  cooldownMs?: number;
}

export class CircuitBreaker {
  private name: string;
  private state: CircuitState = 'CLOSED';
  private failureCount = 0;
  private readonly failureThreshold: number;
  private readonly cooldownMs: number;
  private lastFailureTime = 0;

  constructor(options: CircuitBreakerOptions) {
    this.name = options.name;
    this.failureThreshold = options.failureThreshold || 5;
    this.cooldownMs = options.cooldownMs || 30000;
  }

  public getState(): CircuitState {
    if (this.state === 'OPEN') {
      const now = Date.now();
      if (now - this.lastFailureTime >= this.cooldownMs) {
        this.state = 'HALF_OPEN';
        logger.info(`Circuit breaker [${this.name}] entered HALF_OPEN state; probing downstream service`);
      }
    }
    return this.state;
  }

  public isOpen(): boolean {
    return this.getState() === 'OPEN';
  }

  public recordSuccess(): void {
    if (this.state !== 'CLOSED') {
      logger.info(`Circuit breaker [${this.name}] recovered and CLOSED`);
    }
    this.failureCount = 0;
    this.state = 'CLOSED';
  }

  public recordFailure(errorMsg?: string): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.state === 'HALF_OPEN' || this.failureCount >= this.failureThreshold) {
      this.state = 'OPEN';
      logger.error(`[AI_CIRCUIT_OPEN] Circuit breaker [${this.name}] TRIPPED OPEN. Downstream calls will be bypassed.`, {
        breakerName: this.name,
        failureCount: this.failureCount,
        threshold: this.failureThreshold,
        cooldownMs: this.cooldownMs,
        error: errorMsg,
      });
    }
  }

  /**
   * Executes an operation with circuit protection.
   * If the circuit is open, immediately invokes fallback without calling the external service.
   */
  async execute<T>(operation: () => Promise<T>, fallback: () => Promise<T> | T): Promise<T> {
    if (this.isOpen()) {
      logger.warn(`Circuit [${this.name}] is OPEN. Executing fallback immediately.`, {
        breakerName: this.name,
      });
      return fallback();
    }

    try {
      const result = await operation();
      this.recordSuccess();
      return result;
    } catch (err) {
      this.recordFailure((err as Error).message);
      return fallback();
    }
  }
}

export const aiCircuitBreaker = new CircuitBreaker({
  name: 'python-ai-engine',
  failureThreshold: 5,
  cooldownMs: 30000,
});
