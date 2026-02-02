/**
 * Nimbus - AWS Security Assessment MCP Server - Utility Module
 * 
 * Features:
 * - Caching for repeated API calls
 * - Rate limiting protection
 * - Retry logic with exponential backoff
 * - Error handling utilities
 * - Input validation and sanitization (OWASP MCP05)
 * - Audit logging (OWASP MCP08)
 */

// ============================================
// SECURITY: INPUT VALIDATION (OWASP MCP05)
// ============================================

/**
 * Valid AWS region pattern
 */
const AWS_REGION_PATTERN = /^[a-z]{2}-[a-z]+-\d{1,2}$/;

/**
 * Valid AWS resource ID patterns
 */
const AWS_PATTERNS = {
  region: AWS_REGION_PATTERN,
  accountId: /^\d{12}$/,
  arn: /^arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:.+$/,
  bucketName: /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/,
  instanceId: /^i-[a-f0-9]{8,17}$/,
  roleArn: /^arn:aws:iam::\d{12}:role\/[\w+=,.@-]+$/,
  clusterName: /^[a-zA-Z][a-zA-Z0-9-_]{0,99}$/,
  functionName: /^[a-zA-Z0-9-_]{1,140}$/,
};

/**
 * Validate and sanitize AWS region input
 * @param region - Raw region input
 * @param allowSpecial - Allow 'all' or 'common' special values
 */
export function validateRegion(region: string | undefined, allowSpecial: boolean = true): string {
  if (!region) {
    return process.env.AWS_REGION || 'us-east-1';
  }
  
  const sanitized = region.trim().toLowerCase();
  
  // Allow special values for multi-region scans
  if (allowSpecial && (sanitized === 'all' || sanitized === 'common')) {
    return sanitized;
  }
  
  if (!AWS_REGION_PATTERN.test(sanitized)) {
    throw new Error(`Invalid AWS region format: ${region}. Expected format: us-east-1`);
  }
  
  return sanitized;
}

/**
 * Validate generic string input (prevents injection)
 * @param input - Raw input string
 * @param maxLength - Maximum allowed length
 * @param pattern - Optional regex pattern to validate against
 */
export function validateInput(
  input: string | undefined,
  options: {
    required?: boolean;
    maxLength?: number;
    pattern?: RegExp;
    patternName?: string;
    allowedValues?: string[];
  } = {}
): string | undefined {
  if (input === undefined || input === null || input === '') {
    if (options.required) {
      throw new Error('Required input is missing');
    }
    return undefined;
  }
  
  // Sanitize: trim and remove control characters
  const sanitized = input.toString().trim().replace(/[\x00-\x1f\x7f]/g, '');
  
  // Length check
  const maxLen = options.maxLength || 1000;
  if (sanitized.length > maxLen) {
    throw new Error(`Input exceeds maximum length of ${maxLen} characters`);
  }
  
  // Allowed values check
  if (options.allowedValues && !options.allowedValues.includes(sanitized)) {
    throw new Error(`Invalid value: ${sanitized}. Allowed: ${options.allowedValues.join(', ')}`);
  }
  
  // Pattern validation
  if (options.pattern && !options.pattern.test(sanitized)) {
    const name = options.patternName || 'input';
    throw new Error(`Invalid ${name} format: ${sanitized}`);
  }
  
  return sanitized;
}

/**
 * Validate AWS resource identifiers
 */
export function validateAWSResource(
  value: string | undefined,
  resourceType: keyof typeof AWS_PATTERNS,
  required: boolean = false
): string | undefined {
  if (!value && !required) return undefined;
  if (!value && required) {
    throw new Error(`${resourceType} is required`);
  }
  
  const pattern = AWS_PATTERNS[resourceType];
  if (!pattern) {
    throw new Error(`Unknown resource type: ${resourceType}`);
  }
  
  return validateInput(value, {
    required,
    pattern,
    patternName: resourceType,
  });
}

// ============================================
// SECURITY: AUDIT LOGGING (OWASP MCP08)
// ============================================

type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'SECURITY';

interface AuditLogEntry {
  timestamp: string;
  level: LogLevel;
  tool: string;
  action: string;
  region?: string;
  accountId?: string;
  input?: Record<string, any>;
  result?: 'SUCCESS' | 'FAILURE' | 'PARTIAL';
  duration?: number;
  error?: string;
  findings?: number;
}

class AuditLogger {
  private logs: AuditLogEntry[] = [];
  private maxLogs: number = 1000;
  private enabled: boolean = true;

  /**
   * Log a tool invocation
   */
  logToolCall(entry: Omit<AuditLogEntry, 'timestamp'>): void {
    if (!this.enabled) return;
    
    const logEntry: AuditLogEntry = {
      ...entry,
      timestamp: new Date().toISOString(),
    };
    
    this.logs.push(logEntry);
    
    // Trim old logs
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }
    
    // Output to stderr for real-time monitoring
    const levelColors: Record<LogLevel, string> = {
      DEBUG: '\x1b[36m',
      INFO: '\x1b[32m',
      WARN: '\x1b[33m',
      ERROR: '\x1b[31m',
      SECURITY: '\x1b[35m',
    };
    const reset = '\x1b[0m';
    const color = levelColors[entry.level] || reset;
    
    console.error(
      `${color}[${logEntry.timestamp}] [${entry.level}] ${entry.tool}: ${entry.action}${reset}` +
      (entry.region ? ` (region: ${entry.region})` : '') +
      (entry.result ? ` -> ${entry.result}` : '') +
      (entry.findings !== undefined ? ` [${entry.findings} findings]` : '') +
      (entry.error ? ` ERROR: ${entry.error}` : '')
    );
  }

  /**
   * Log security-relevant events
   */
  logSecurity(tool: string, action: string, details?: Record<string, any>): void {
    this.logToolCall({
      level: 'SECURITY',
      tool,
      action,
      input: details,
    });
  }

  /**
   * Get audit log entries
   */
  getLogs(filter?: { level?: LogLevel; tool?: string; since?: Date }): AuditLogEntry[] {
    let filtered = [...this.logs];
    
    if (filter?.level) {
      filtered = filtered.filter(l => l.level === filter.level);
    }
    if (filter?.tool) {
      filtered = filtered.filter(l => l.tool === filter.tool);
    }
    if (filter?.since) {
      const since = filter.since.getTime();
      filtered = filtered.filter(l => new Date(l.timestamp).getTime() >= since);
    }
    
    return filtered;
  }

  /**
   * Get audit statistics
   */
  getStats(): {
    totalCalls: number;
    byTool: Record<string, number>;
    byResult: Record<string, number>;
    securityEvents: number;
  } {
    const byTool: Record<string, number> = {};
    const byResult: Record<string, number> = {};
    let securityEvents = 0;
    
    for (const log of this.logs) {
      byTool[log.tool] = (byTool[log.tool] || 0) + 1;
      if (log.result) {
        byResult[log.result] = (byResult[log.result] || 0) + 1;
      }
      if (log.level === 'SECURITY') {
        securityEvents++;
      }
    }
    
    return {
      totalCalls: this.logs.length,
      byTool,
      byResult,
      securityEvents,
    };
  }

  /**
   * Clear logs
   */
  clear(): void {
    this.logs = [];
  }

  /**
   * Enable/disable logging
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }
}

// Global audit logger instance
export const auditLogger = new AuditLogger();

/**
 * Wrapper to audit a tool call
 */
export async function withAudit<T>(
  toolName: string,
  action: string,
  fn: () => Promise<T>,
  options: {
    region?: string;
    input?: Record<string, any>;
  } = {}
): Promise<T> {
  const startTime = Date.now();
  
  try {
    const result = await fn();
    
    auditLogger.logToolCall({
      level: 'INFO',
      tool: toolName,
      action,
      region: options.region,
      input: sanitizeForLog(options.input),
      result: 'SUCCESS',
      duration: Date.now() - startTime,
    });
    
    return result;
  } catch (error: any) {
    auditLogger.logToolCall({
      level: 'ERROR',
      tool: toolName,
      action,
      region: options.region,
      input: sanitizeForLog(options.input),
      result: 'FAILURE',
      duration: Date.now() - startTime,
      error: error.message,
    });
    
    throw error;
  }
}

/**
 * Remove sensitive data from log entries
 */
function sanitizeForLog(input?: Record<string, any>): Record<string, any> | undefined {
  if (!input) return undefined;
  
  const sensitiveKeys = ['password', 'secret', 'token', 'key', 'credential', 'auth'];
  const sanitized: Record<string, any> = {};
  
  for (const [key, value] of Object.entries(input)) {
    const iseSensitive = sensitiveKeys.some(s => key.toLowerCase().includes(s));
    sanitized[key] = iseSensitive ? '[REDACTED]' : value;
  }
  
  return sanitized;
}

// ============================================
// CACHING
// ============================================

interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
}

class Cache {
  private store: Map<string, CacheEntry<any>> = new Map();
  private defaultTTL: number = 300000; // 5 minutes in milliseconds

  /**
   * Get cached value or undefined if expired/missing
   */
  get<T>(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.store.delete(key);
      return undefined;
    }
    
    return entry.data as T;
  }

  /**
   * Set value in cache with optional TTL
   */
  set<T>(key: string, data: T, ttl?: number): void {
    this.store.set(key, {
      data,
      timestamp: Date.now(),
      ttl: ttl || this.defaultTTL,
    });
  }

  /**
   * Check if key exists and is not expired
   */
  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  /**
   * Clear specific key or all cache
   */
  clear(key?: string): void {
    if (key) {
      this.store.delete(key);
    } else {
      this.store.clear();
    }
  }

  /**
   * Get cache stats
   */
  stats(): { size: number; keys: string[] } {
    return {
      size: this.store.size,
      keys: Array.from(this.store.keys()),
    };
  }
}

// Global cache instance
export const cache = new Cache();

/**
 * Cache decorator for async functions
 * @param keyPrefix - Prefix for cache key
 * @param ttl - Time to live in milliseconds
 */
export function withCache<T>(
  keyPrefix: string,
  fn: (...args: any[]) => Promise<T>,
  ttl?: number
): (...args: any[]) => Promise<T> {
  return async (...args: any[]): Promise<T> => {
    const cacheKey = `${keyPrefix}:${JSON.stringify(args)}`;
    
    const cached = cache.get<T>(cacheKey);
    if (cached !== undefined) {
      return cached;
    }
    
    const result = await fn(...args);
    cache.set(cacheKey, result, ttl);
    return result;
  };
}

// ============================================
// RATE LIMITING
// ============================================

interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}

class RateLimiter {
  private requests: Map<string, number[]> = new Map();
  private config: RateLimitConfig;

  constructor(config: RateLimitConfig = { maxRequests: 100, windowMs: 60000 }) {
    this.config = config;
  }

  /**
   * Check if request is allowed under rate limit
   */
  isAllowed(key: string = 'default'): boolean {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    
    let timestamps = this.requests.get(key) || [];
    timestamps = timestamps.filter(t => t > windowStart);
    
    if (timestamps.length >= this.config.maxRequests) {
      return false;
    }
    
    timestamps.push(now);
    this.requests.set(key, timestamps);
    return true;
  }

  /**
   * Wait until request is allowed
   */
  async waitForSlot(key: string = 'default'): Promise<void> {
    while (!this.isAllowed(key)) {
      await sleep(100);
    }
  }

  /**
   * Get remaining requests in current window
   */
  remaining(key: string = 'default'): number {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    const timestamps = (this.requests.get(key) || []).filter(t => t > windowStart);
    return Math.max(0, this.config.maxRequests - timestamps.length);
  }

  /**
   * Reset rate limiter
   */
  reset(key?: string): void {
    if (key) {
      this.requests.delete(key);
    } else {
      this.requests.clear();
    }
  }
}

// Global rate limiter instances for different services
export const rateLimiters = {
  ec2: new RateLimiter({ maxRequests: 50, windowMs: 60000 }),
  iam: new RateLimiter({ maxRequests: 30, windowMs: 60000 }),
  s3: new RateLimiter({ maxRequests: 50, windowMs: 60000 }),
  lambda: new RateLimiter({ maxRequests: 30, windowMs: 60000 }),
  rds: new RateLimiter({ maxRequests: 20, windowMs: 60000 }),
  default: new RateLimiter({ maxRequests: 100, windowMs: 60000 }),
};

// ============================================
// RETRY LOGIC WITH EXPONENTIAL BACKOFF
// ============================================

interface RetryConfig {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  retryableErrors: string[];
}

const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  retryableErrors: [
    'ThrottlingException',
    'TooManyRequestsException',
    'ServiceUnavailable',
    'RequestLimitExceeded',
    'ProvisionedThroughputExceededException',
    'Throttling',
    'ECONNRESET',
    'ETIMEDOUT',
    'ENOTFOUND',
    'NetworkingError',
  ],
};

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Calculate exponential backoff delay with jitter
 */
function calculateBackoff(attempt: number, config: RetryConfig): number {
  const exponentialDelay = config.baseDelayMs * Math.pow(2, attempt);
  const jitter = Math.random() * 1000;
  return Math.min(exponentialDelay + jitter, config.maxDelayMs);
}

/**
 * Check if error is retryable
 */
function isRetryableError(error: any, config: RetryConfig): boolean {
  if (!error) return false;
  
  const errorName = error.name || error.code || '';
  const errorMessage = error.message || '';
  
  return config.retryableErrors.some(
    retryable => 
      errorName.includes(retryable) || 
      errorMessage.includes(retryable)
  );
}

/**
 * Execute function with retry logic
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  config: Partial<RetryConfig> = {}
): Promise<T> {
  const fullConfig = { ...DEFAULT_RETRY_CONFIG, ...config };
  let lastError: any;
  
  for (let attempt = 0; attempt <= fullConfig.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error: any) {
      lastError = error;
      
      if (attempt === fullConfig.maxRetries || !isRetryableError(error, fullConfig)) {
        throw error;
      }
      
      const delay = calculateBackoff(attempt, fullConfig);
      console.error(`Retry attempt ${attempt + 1}/${fullConfig.maxRetries} after ${delay}ms: ${error.message}`);
      await sleep(delay);
    }
  }
  
  throw lastError;
}

/**
 * Wrapper that combines rate limiting and retry logic
 */
export async function safeApiCall<T>(
  fn: () => Promise<T>,
  options: {
    service?: keyof typeof rateLimiters;
    cacheKey?: string;
    cacheTTL?: number;
    retryConfig?: Partial<RetryConfig>;
  } = {}
): Promise<T> {
  // Check cache first
  if (options.cacheKey) {
    const cached = cache.get<T>(options.cacheKey);
    if (cached !== undefined) {
      return cached;
    }
  }
  
  // Wait for rate limit slot
  const limiter = rateLimiters[options.service || 'default'];
  await limiter.waitForSlot();
  
  // Execute with retry
  const result = await withRetry(fn, options.retryConfig);
  
  // Cache result
  if (options.cacheKey) {
    cache.set(options.cacheKey, result, options.cacheTTL);
  }
  
  return result;
}

// ============================================
// ERROR HANDLING UTILITIES
// ============================================

export interface ApiError {
  code: string;
  message: string;
  service: string;
  retryable: boolean;
  details?: any;
}

/**
 * Parse AWS SDK errors into standardized format
 */
export function parseAWSError(error: any, service: string = 'AWS'): ApiError {
  return {
    code: error.name || error.code || 'UnknownError',
    message: error.message || 'An unknown error occurred',
    service,
    retryable: isRetryableError(error, DEFAULT_RETRY_CONFIG),
    details: {
      requestId: error.$metadata?.requestId,
      httpStatusCode: error.$metadata?.httpStatusCode,
    },
  };
}

/**
 * Format error for user-friendly output
 */
export function formatError(error: ApiError): string {
  let message = `[FAIL] ${error.service} Error: ${error.message}`;
  
  if (error.code !== 'UnknownError') {
    message += ` (${error.code})`;
  }
  
  if (error.retryable) {
    message += '\n[TIP] This error is retryable - the operation was automatically retried.';
  }
  
  return message;
}

/**
 * Safe execution wrapper with error formatting
 */
export async function safeExecute<T>(
  fn: () => Promise<T>,
  options: {
    service?: string;
    errorPrefix?: string;
    defaultValue?: T;
  } = {}
): Promise<{ success: boolean; data?: T; error?: string }> {
  try {
    const data = await fn();
    return { success: true, data };
  } catch (error: any) {
    const parsedError = parseAWSError(error, options.service);
    const errorMessage = options.errorPrefix 
      ? `${options.errorPrefix}: ${parsedError.message}`
      : parsedError.message;
    
    if (options.defaultValue !== undefined) {
      return { success: false, data: options.defaultValue, error: errorMessage };
    }
    
    return { success: false, error: errorMessage };
  }
}

// ============================================
// BATCH PROCESSING UTILITIES
// ============================================

/**
 * Process items in batches with rate limiting
 */
export async function batchProcess<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  options: {
    batchSize?: number;
    delayBetweenBatches?: number;
    service?: keyof typeof rateLimiters;
  } = {}
): Promise<{ results: R[]; errors: Array<{ item: T; error: string }> }> {
  const batchSize = options.batchSize || 10;
  const delay = options.delayBetweenBatches || 1000;
  
  const results: R[] = [];
  const errors: Array<{ item: T; error: string }> = [];
  
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    
    const batchResults = await Promise.allSettled(
      batch.map(item => safeApiCall(() => processor(item), { service: options.service }))
    );
    
    batchResults.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      } else {
        errors.push({ item: batch[index], error: result.reason?.message || 'Unknown error' });
      }
    });
    
    // Delay between batches
    if (i + batchSize < items.length) {
      await sleep(delay);
    }
  }
  
  return { results, errors };
}

// ============================================
// EXPORTS
// ============================================

export { Cache, RateLimiter, AWS_PATTERNS };
