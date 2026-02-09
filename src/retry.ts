/**
 * Nimbus AWS MCP - Retry Logic for Transient Failures
 * Version 1.5.6
 * 
 * Provides exponential backoff retry for:
 * - Rate limiting
 * - Timeout errors
 * - Network failures
 * - Transient AWS API errors
 */

import { logger } from './logging.js';
import { MCPError, TimeoutError, RateLimitError, NetworkError } from './errors.js';

export interface RetryOptions {
  maxAttempts?: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  backoffMultiplier?: number;
  retryableErrors?: string[];
  onRetry?: (attempt: number, error: Error, delayMs: number) => void;
}

const DEFAULT_RETRY_OPTIONS: Required<RetryOptions> = {
  maxAttempts: 3,
  initialDelayMs: 1000,
  maxDelayMs: 30000,
  backoffMultiplier: 2,
  retryableErrors: [
    'TimeoutError',
    'RateLimitError',
    'NetworkError',
    'ThrottlingException',
    'RequestLimitExceeded',
    'ServiceUnavailable',
    'InternalError',
    'ECONNRESET',
    'ETIMEDOUT',
    'ENOTFOUND',
  ],
  onRetry: () => {},
};

/**
 * Check if an error is retryable
 */
function isRetryableError(error: unknown, retryableErrors: string[]): boolean {
  if (error instanceof MCPError) {
    return (error as MCPError).retryable;
  }

  if (error instanceof Error) {
    // Check error name/message against retryable patterns
    const errorStr = `${error.name}:${error.message}`;
    return retryableErrors.some(pattern => 
      errorStr.includes(pattern) || error.name === pattern
    );
  }

  return false;
}

/**
 * Calculate delay with exponential backoff and jitter
 */
function calculateDelay(
  attempt: number,
  initialDelayMs: number,
  maxDelayMs: number,
  backoffMultiplier: number
): number {
  const exponentialDelay = initialDelayMs * Math.pow(backoffMultiplier, attempt - 1);
  const cappedDelay = Math.min(exponentialDelay, maxDelayMs);
  
  // Add jitter (±25% random variation)
  const jitter = cappedDelay * 0.25 * (Math.random() * 2 - 1);
  return Math.floor(cappedDelay + jitter);
}

/**
 * Sleep for specified milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry a function with exponential backoff
 */
export async function retry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {},
  operationName: string = 'operation'
): Promise<T> {
  const opts = { ...DEFAULT_RETRY_OPTIONS, ...options };
  let lastError: unknown;

  for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      logger.debug(`${operationName}: Attempt ${attempt}/${opts.maxAttempts}`);
      return await fn();
    } catch (error) {
      lastError = error;

      // Check if error is retryable
      if (!isRetryableError(error, opts.retryableErrors)) {
        logger.debug(`${operationName}: Non-retryable error, throwing immediately`, {
          error: error instanceof Error ? error.message : String(error),
        });
        throw error;
      }

      // Don't retry on last attempt
      if (attempt === opts.maxAttempts) {
        logger.warn(`${operationName}: Max attempts reached (${opts.maxAttempts}), giving up`, {
          error: error instanceof Error ? error.message : String(error),
        });
        break;
      }

      // Calculate delay and retry
      const delayMs = calculateDelay(
        attempt,
        opts.initialDelayMs,
        opts.maxDelayMs,
        opts.backoffMultiplier
      );

      logger.info(`${operationName}: Retrying after ${delayMs}ms (attempt ${attempt + 1}/${opts.maxAttempts})`, {
        error: error instanceof Error ? error.message : String(error),
        delayMs,
        attempt: attempt + 1,
      });

      opts.onRetry(attempt, error as Error, delayMs);
      await sleep(delayMs);
    }
  }

  // All attempts failed
  throw lastError;
}

/**
 * Retry wrapper with timeout
 */
export async function retryWithTimeout<T>(
  fn: () => Promise<T>,
  timeoutMs: number,
  retryOptions: RetryOptions = {},
  operationName: string = 'operation'
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeoutHandle = setTimeout(() => {
      reject(new TimeoutError(operationName, timeoutMs));
    }, timeoutMs);

    retry(fn, retryOptions, operationName)
      .then(result => {
        clearTimeout(timeoutHandle);
        resolve(result);
      })
      .catch(error => {
        clearTimeout(timeoutHandle);
        reject(error);
      });
  });
}

/**
 * Decorator for automatic retry
 */
export function withRetry(options: RetryOptions = {}) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      return retry(
        () => originalMethod.apply(this, args),
        options,
        propertyKey
      );
    };

    return descriptor;
  };
}

/**
 * Rate limiter with token bucket algorithm
 */
export class RateLimiter {
  private tokens: number;
  private maxTokens: number;
  private refillRate: number; // tokens per second
  private lastRefill: number;

  constructor(maxTokens: number, refillRate: number) {
    this.tokens = maxTokens;
    this.maxTokens = maxTokens;
    this.refillRate = refillRate;
    this.lastRefill = Date.now();
  }

  /**
   * Refill tokens based on time elapsed
   */
  private refill(): void {
    const now = Date.now();
    const elapsedSeconds = (now - this.lastRefill) / 1000;
    const tokensToAdd = elapsedSeconds * this.refillRate;

    this.tokens = Math.min(this.maxTokens, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }

  /**
   * Try to acquire tokens (non-blocking)
   */
  tryAcquire(tokens: number = 1): boolean {
    this.refill();

    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }

    return false;
  }

  /**
   * Acquire tokens (blocking with wait)
   */
  async acquire(tokens: number = 1): Promise<void> {
    this.refill();

    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return;
    }

    // Calculate wait time
    const tokensNeeded = tokens - this.tokens;
    const waitMs = (tokensNeeded / this.refillRate) * 1000;

    logger.debug(`Rate limit: Waiting ${waitMs}ms for ${tokens} tokens`);
    await sleep(waitMs);

    this.refill();
    this.tokens -= tokens;
  }

  /**
   * Get remaining tokens
   */
  getAvailableTokens(): number {
    this.refill();
    return Math.floor(this.tokens);
  }

  /**
   * Reset rate limiter
   */
  reset(): void {
    this.tokens = this.maxTokens;
    this.lastRefill = Date.now();
  }
}

/**
 * Circuit breaker pattern for failing services
 */
export class CircuitBreaker {
  private failureCount: number = 0;
  private successCount: number = 0;
  private lastFailureTime: number = 0;
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';

  constructor(
    private failureThreshold: number = 5,
    private resetTimeoutMs: number = 60000,
    private successThreshold: number = 2
  ) {}

  /**
   * Execute function with circuit breaker
   */
  async execute<T>(fn: () => Promise<T>, operationName: string = 'operation'): Promise<T> {
    // Check if circuit is open
    if (this.state === 'OPEN') {
      const timeSinceLastFailure = Date.now() - this.lastFailureTime;
      
      if (timeSinceLastFailure >= this.resetTimeoutMs) {
        logger.info(`Circuit breaker: Transitioning to HALF_OPEN for ${operationName}`);
        this.state = 'HALF_OPEN';
      } else {
        throw new Error(
          `Circuit breaker OPEN for ${operationName}. Try again in ${Math.ceil((this.resetTimeoutMs - timeSinceLastFailure) / 1000)}s`
        );
      }
    }

    try {
      const result = await fn();
      
      this.onSuccess(operationName);
      return result;
    } catch (error) {
      this.onFailure(operationName);
      throw error;
    }
  }

  private onSuccess(operationName: string): void {
    this.successCount++;

    if (this.state === 'HALF_OPEN') {
      if (this.successCount >= this.successThreshold) {
        logger.info(`Circuit breaker: Transitioning to CLOSED for ${operationName}`);
        this.state = 'CLOSED';
        this.failureCount = 0;
        this.successCount = 0;
      }
    } else {
      // Reset failure count on success
      this.failureCount = 0;
    }
  }

  private onFailure(operationName: string): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    this.successCount = 0;

    if (this.failureCount >= this.failureThreshold) {
      logger.warn(`Circuit breaker: Opening circuit for ${operationName}`, {
        failureCount: this.failureCount,
        threshold: this.failureThreshold,
      });
      this.state = 'OPEN';
    }
  }

  getState(): string {
    return this.state;
  }

  reset(): void {
    this.state = 'CLOSED';
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = 0;
  }
}
