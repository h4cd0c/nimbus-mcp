/**
 * Nimbus AWS MCP - Logging and Performance Tracking
 * Version 1.5.6
 * 
 * Provides:
 * - Structured logging with levels
 * - PII redaction
 * - Performance metrics
 * - Request/response logging
 */

export enum LogLevel {
  DEBUG = 'DEBUG',
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
  SECURITY = 'SECURITY',
}

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  data?: Record<string, any>;
  tool?: string;
  duration?: number;
  requestId?: string;
}

interface PerformanceMetrics {
  toolName: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  success: boolean;
  errorCode?: string;
  apiCalls?: number;
  cacheHits?: number;
  cacheMisses?: number;
}

/**
 * PII patterns to redact from logs
 */
const PII_PATTERNS = [
  // AWS Access Keys
  { pattern: /(AKIA[0-9A-Z]{16})/gi, replacement: 'AKIA***REDACTED***' },
  // AWS Secret Keys
  { pattern: /([A-Za-z0-9/+=]{40})/g, replacement: '***SECRET_REDACTED***' },
  // Email addresses
  { pattern: /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g, replacement: '***EMAIL_REDACTED***' },
  // IP addresses (be conservative, some IPs are not PII)
  // { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '***IP_REDACTED***' },
  // AWS Account IDs (12 digits)
  { pattern: /\b\d{12}\b/g, replacement: '***ACCOUNT_REDACTED***' },
  // Session tokens
  { pattern: /(FwoG[A-Za-z0-9+/=]{100,})/g, replacement: '***SESSION_TOKEN_REDACTED***' },
];

/**
 * Sensitive field names to redact
 */
const SENSITIVE_FIELDS = new Set([
  'password',
  'secret',
  'token',
  'accessKey',
  'secretKey',
  'sessionToken',
  'authToken',
  'apiKey',
  'privateKey',
  'credential',
]);

class Logger {
  private minLevel: LogLevel;
  private logs: LogEntry[] = [];
  private maxLogs: number = 1000;
  private enableConsole: boolean;

  constructor(minLevel: LogLevel = LogLevel.INFO, enableConsole: boolean = true) {
    this.minLevel = minLevel;
    this.enableConsole = enableConsole;
  }

  /**
   * Redact PII from log data
   */
  private redactPII(data: any): any {
    if (typeof data === 'string') {
      let redacted = data;
      for (const { pattern, replacement } of PII_PATTERNS) {
        redacted = redacted.replace(pattern, replacement);
      }
      return redacted;
    }

    if (Array.isArray(data)) {
      return data.map(item => this.redactPII(item));
    }

    if (data && typeof data === 'object') {
      const redacted: Record<string, any> = {};
      for (const [key, value] of Object.entries(data)) {
        // Redact sensitive fields completely
        if (SENSITIVE_FIELDS.has(key.toLowerCase())) {
          redacted[key] = '***REDACTED***';
        } else {
          redacted[key] = this.redactPII(value);
        }
      }
      return redacted;
    }

    return data;
  }

  /**
   * Check if log level should be logged
   */
  private shouldLog(level: LogLevel): boolean {
    const levels = [LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR, LogLevel.SECURITY];
    const minIndex = levels.indexOf(this.minLevel);
    const currentIndex = levels.indexOf(level);
    return currentIndex >= minIndex;
  }

  /**
   * Log a message
   */
  private log(
    level: LogLevel,
    message: string,
    data?: Record<string, any>,
    tool?: string,
    duration?: number,
    requestId?: string
  ): void {
    if (!this.shouldLog(level)) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message: this.redactPII(message),
      data: data ? this.redactPII(data) : undefined,
      tool,
      duration,
      requestId,
    };

    // Store in memory
    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs.shift(); // Remove oldest
    }

    // Output to console (stderr to not interfere with MCP protocol)
    if (this.enableConsole) {
      const prefix = `[${entry.timestamp}] [${level}]${tool ? ` [${tool}]` : ''}`;
      const logMessage = `${prefix} ${message}`;
      
      if (process.env.NODE_ENV !== 'production') {
        console.error(logMessage);
        if (data) {
          console.error(JSON.stringify(entry.data, null, 2));
        }
      }
    }
  }

  debug(message: string, data?: Record<string, any>, tool?: string): void {
    this.log(LogLevel.DEBUG, message, data, tool);
  }

  info(message: string, data?: Record<string, any>, tool?: string): void {
    this.log(LogLevel.INFO, message, data, tool);
  }

  warn(message: string, data?: Record<string, any>, tool?: string): void {
    this.log(LogLevel.WARN, message, data, tool);
  }

  error(message: string, data?: Record<string, any>, tool?: string): void {
    this.log(LogLevel.ERROR, message, data, tool);
  }

  security(message: string, data?: Record<string, any>, tool?: string): void {
    this.log(LogLevel.SECURITY, message, data, tool);
  }

  /**
   * Get recent logs
   */
  getLogs(level?: LogLevel, limit?: number): LogEntry[] {
    let filtered = level 
      ? this.logs.filter(log => log.level === level)
      : this.logs;

    if (limit) {
      filtered = filtered.slice(-limit);
    }

    return filtered;
  }

  /**
   * Clear logs
   */
  clearLogs(): void {
    this.logs = [];
  }

  /**
   * Set minimum log level
   */
  setLevel(level: LogLevel): void {
    this.minLevel = level;
  }
}

/**
 * Performance tracker for operations
 */
class PerformanceTracker {
  private metrics: Map<string, PerformanceMetrics> = new Map();
  private maxMetrics: number = 500;

  /**
   * Start tracking an operation
   */
  start(toolName: string, requestId?: string): string {
    const id = requestId || `${toolName}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    this.metrics.set(id, {
      toolName,
      startTime: Date.now(),
      success: false,
      apiCalls: 0,
      cacheHits: 0,
      cacheMisses: 0,
    });

    // Cleanup old metrics
    if (this.metrics.size > this.maxMetrics) {
      const oldestKey = this.metrics.keys().next().value;
      if (oldestKey) {
        this.metrics.delete(oldestKey);
      }
    }

    return id;
  }

  /**
   * End tracking an operation
   */
  end(
    id: string,
    success: boolean = true,
    errorCode?: string
  ): PerformanceMetrics | null {
    const metric = this.metrics.get(id);
    if (!metric) return null;

    metric.endTime = Date.now();
    metric.duration = metric.endTime - metric.startTime;
    metric.success = success;
    metric.errorCode = errorCode;

    logger.info(
      `Performance: ${metric.toolName} completed in ${metric.duration}ms`,
      {
        duration: metric.duration,
        success,
        apiCalls: metric.apiCalls,
        cacheHits: metric.cacheHits,
        cacheMisses: metric.cacheMisses,
      },
      metric.toolName
    );

    return metric;
  }

  /**
   * Record API call
   */
  recordAPICall(id: string): void {
    const metric = this.metrics.get(id);
    if (metric) {
      metric.apiCalls = (metric.apiCalls || 0) + 1;
    }
  }

  /**
   * Record cache hit
   */
  recordCacheHit(id: string): void {
    const metric = this.metrics.get(id);
    if (metric) {
      metric.cacheHits = (metric.cacheHits || 0) + 1;
    }
  }

  /**
   * Record cache miss
   */
  recordCacheMiss(id: string): void {
    const metric = this.metrics.get(id);
    if (metric) {
      metric.cacheMisses = (metric.cacheMisses || 0) + 1;
    }
  }

  /**
   * Get metrics summary
   */
  getSummary(): {
    totalOperations: number;
    successRate: number;
    averageDuration: number;
    slowestOperation: PerformanceMetrics | null;
  } {
    const completed = Array.from(this.metrics.values()).filter(m => m.endTime);
    
    if (completed.length === 0) {
      return {
        totalOperations: 0,
        successRate: 0,
        averageDuration: 0,
        slowestOperation: null,
      };
    }

    const successful = completed.filter(m => m.success).length;
    const totalDuration = completed.reduce((sum, m) => sum + (m.duration || 0), 0);
    const slowest = completed.reduce((max, m) => 
      !max || (m.duration || 0) > (max.duration || 0) ? m : max
    );

    return {
      totalOperations: completed.length,
      successRate: successful / completed.length,
      averageDuration: totalDuration / completed.length,
      slowestOperation: slowest,
    };
  }

  /**
   * Get metrics for a specific tool
   */
  getToolMetrics(toolName: string): PerformanceMetrics[] {
    return Array.from(this.metrics.values())
      .filter(m => m.toolName === toolName && m.endTime);
  }
}

// Export singleton instances
export const logger = new Logger(
  process.env.LOG_LEVEL as LogLevel || LogLevel.INFO,
  process.env.NODE_ENV !== 'production'
);

export const performanceTracker = new PerformanceTracker();

/**
 * Decorator for automatic performance tracking
 */
export function trackPerformance(toolName: string) {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const trackingId = performanceTracker.start(toolName);
      
      try {
        const result = await originalMethod.apply(this, args);
        performanceTracker.end(trackingId, true);
        return result;
      } catch (error) {
        const errorCode = error instanceof Error ? error.name : 'UNKNOWN_ERROR';
        performanceTracker.end(trackingId, false, errorCode);
        throw error;
      }
    };

    return descriptor;
  };
}
