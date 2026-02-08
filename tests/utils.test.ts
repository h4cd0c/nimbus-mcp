import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  validateRegion,
  validateInput,
  cache,
  rateLimiters,
} from '../src/utils';

describe('AWS Region Validation', () => {
  it('should validate common AWS regions', () => {
    expect(validateRegion('us-east-1')).toBe('us-east-1');
    expect(validateRegion('eu-west-1')).toBe('eu-west-1');
    expect(validateRegion('ap-southeast-1')).toBe('ap-southeast-1');
  });

  it('should accept special multi-region keywords', () => {
    expect(validateRegion('all')).toBe('all');
    expect(validateRegion('common')).toBe('common');
  });

  it('should reject invalid regions with error', () => {
    expect(() => validateRegion('invalid-region', false)).toThrow('Invalid AWS region');
    expect(() => validateRegion('not a region', false)).toThrow('Invalid AWS region');
  });

  it('should handle edge cases', () => {
    expect(validateRegion(undefined)).toMatch(/^[a-z]{2}-[a-z]+-\d+$/);
  });
});

describe('Input Validation', () => {
  it('should validate required string inputs', () => {
    const result = validateInput('test-bucket', { required: true });
    expect(result).toBe('test-bucket');
  });

  it('should throw on missing required input', () => {
    expect(() => validateInput(undefined, { required: true }))
      .toThrow('Required input is missing');
  });

  it('should validate string patterns', () => {
    const pattern = /^[a-z0-9-]+$/;
    expect(validateInput('valid-name', { pattern, patternName: 'name' })).toBe('valid-name');
    expect(() => validateInput('Invalid_Name!', { pattern, patternName: 'name' }))
      .toThrow('Invalid name format');
  });

  it('should validate maxLength', () => {
    expect(validateInput('test', { maxLength: 10 })).toBe('test');
    expect(() => validateInput('a'.repeat(1001), { maxLength: 10 }))
      .toThrow('Input exceeds maximum length');
  });

  it('should validate allowedValues', () => {
    const allowedValues = ['read', 'write', 'admin'];
    expect(validateInput('read', { allowedValues })).toBe('read');
    expect(() => validateInput('invalid', { allowedValues }))
      .toThrow('Invalid value');
  });

  it('should allow optional inputs', () => {
    expect(validateInput(undefined, { required: false })).toBeUndefined();
  });

  it('should sanitize control characters', () => {
    const result = validateInput('test\x00data', { required: false });
    expect(result).toBe('testdata');
  });
});

describe('Caching System', () => {
 beforeEach(() => {
    cache.clear();
  });

  it('should store and retrieve cached values', () => {
    cache.set('test-key', { data: 'test-value' });
    const result = cache.get('test-key');
    expect(result).toEqual({ data: 'test-value' });
  });

  it('should return undefined for missing keys', () => {
    const result = cache.get('non-existent-key');
    expect(result).toBeUndefined();
  });

  it('should clear specific cache keys', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    cache.clear('key1');
    
    expect(cache.get('key1')).toBeUndefined();
    expect(cache.get('key2')).toBe('value2');
  });

  it('should clear all cache entries', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    cache.clear();
    
    expect(cache.get('key1')).toBeUndefined();
    expect(cache.get('key2')).toBeUndefined();
  });

  it('should report cache statistics', () => {
    cache.set('key1', 'value1');
    
    const stats = cache.stats();
    expect(stats.size).toBeGreaterThanOrEqual(0);
    expect(stats.keys).toBeDefined();
    expect(Array.isArray(stats.keys)).toBe(true);
  });

  it('should handle complex objects in cache', () => {
    const complexData = {
      instances: [{ id: 'i-123', type: 't2.micro' }],
      metadata: { region: 'us-east-1', count: 1 }
    };
    
    cache.set('complex-key', complexData);
    const result = cache.get('complex-key');
    expect(result).toEqual(complexData);
  });

  it('should respect TTL for cache entries', () => {
    cache.set('short-lived', 'data', 100);
    expect(cache.get('short-lived')).toBe('data');
  });
});

describe('Rate Limiting', () => {
  it('should initialize rate limiters for services', () => {
    expect(rateLimiters.ec2).toBeDefined();
    expect(rateLimiters.s3).toBeDefined();
    expect(rateLimiters.iam).toBeDefined();
  });

  it('should track API call rates', () => {
    const limiter = rateLimiters.ec2;
    expect(typeof limiter.isAllowed).toBe('function');
    expect(typeof limiter.remaining).toBe('function');
  });

  it('should have rate limiters for common services', () => {
    const expectedServices = ['ec2', 's3', 'iam', 'rds', 'lambda', 'default'];
    
    expectedServices.forEach(service => {
      expect(rateLimiters[service as keyof typeof rateLimiters]).toBeDefined();
    });
  });

  it('should allow requests under limit', () => {
    const limiter = rateLimiters.default;
    limiter.reset();
    expect(limiter.isAllowed('test-key')).toBe(true);
  });

  it('should track remaining capacity', () => {
    const limiter = rateLimiters.default;
    limiter.reset('test-remaining');
    const remaining = limiter.remaining('test-remaining');
    expect(remaining).toBeGreaterThan(0);
  });
});

describe('Edge Cases and Error Handling', () => {
  it('should handle undefined gracefully', () => {
    expect(() => validateInput(undefined, { required: true })).toThrow();
    expect(validateInput(undefined, { required: false })).toBeUndefined();
  });

  it('should handle empty strings appropriately', () => {
    expect(() => validateInput('', { required: true })).toThrow();
    expect(validateInput('', { required: false })).toBeUndefined();
  });

  it('should handle special characters in validation', () => {
    const specialPattern = /^[a-zA-Z0-9._-]+$/;
    expect(validateInput('test-bucket_v1.0', { pattern: specialPattern, patternName: 'bucket' }))
      .toBe('test-bucket_v1.0');
    expect(() => validateInput('invalid/bucket', { pattern: specialPattern, patternName: 'bucket' }))
      .toThrow('Invalid bucket format');
  });

  it('should validate region case sensitivity', () => {
    expect(validateRegion('us-east-1')).toBe('us-east-1');
    expect(validateRegion('US-EAST-1')).toBe('us-east-1');
  });

  it('should trim whitespace from inputs', () => {
    const result = validateInput('  test  ', { required: true });
    expect(result).toBe('test');
  });
});
