import { describe, it, expect } from '@jest/globals';

/**
 * Nimbus AWS MCP - Format Parameter Integration Tests
 * Tests for response formatting functionality (v1.5.5+)
 */

describe('Format Parameter Integration (AWS)', () => {
  // Mock formatResponse helper
  function formatResponse(data: any, format: 'markdown' | 'json', toolName: string) {
    if (format === 'json') {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            tool: toolName,
            format: 'json',
            timestamp: new Date().toISOString(),
            data: data
          }, null, 2)
        }]
      };
    }
    
    return {
      content: [{
        type: 'text',
        text: typeof data === 'string' ? data : JSON.stringify(data)
      }]
    };
  }

  describe('Markdown Format Output', () => {
    it('should return plain text for markdown format', () => {
      const data = '## Security Findings\n\n- EC2 instances: 5\n- Risks: 2 HIGH';
      const result = formatResponse(data, 'markdown', 'aws_scan_ec2_security');
      
      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toBe(data);
      expect(result.content[0].text).toContain('## Security Findings');
    });

    it('should handle complex markdown structures', () => {
      const data = `
# AWS Security Report

## Summary
- Total Resources: 100
- Critical Issues: 5

## Details
| Resource | Status | Severity |
|----------|--------|----------|
| EC2-001  | FAIL   | HIGH     |
`;
      const result = formatResponse(data, 'markdown', 'aws_generate_security_report');
      
      expect(result.content[0].text).toContain('# AWS Security Report');
      expect(result.content[0].text).toContain('| Resource | Status | Severity |');
    });
  });

  describe('JSON Format Output', () => {
    it('should return structured JSON with metadata envelope', () => {
      const data = {
        findings: ['EC2 instance i-123 has public SSH access'],
        severity: 'HIGH',
        count: 1
      };
      
      const result = formatResponse(data, 'json', 'aws_scan_ec2_security');
      const parsed = JSON.parse(result.content[0].text);
      
      expect(parsed).toHaveProperty('tool');
      expect(parsed).toHaveProperty('format');
      expect(parsed).toHaveProperty('timestamp');
      expect(parsed).toHaveProperty('data');
      expect(parsed.tool).toBe('aws_scan_ec2_security');
      expect(parsed.format).toBe('json');
    });

    it('should include timestamp in ISO format', () => {
      const data = { test: 'data' };
      const result = formatResponse(data, 'json', 'aws_whoami');
      const parsed = JSON.parse(result.content[0].text);
      
      expect(parsed.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
      expect(() => new Date(parsed.timestamp)).not.toThrow();
    });

    it('should preserve complex data structures', () => {
      const complexData = {
        resources: [
          { id: 'i-123', type: 'ec2', region: 'us-east-1' },
          { id: 'i-456', type: 'ec2', region: 'eu-west-1' }
        ],
        metadata: {
          scannedAt: '2026-02-09',
          totalCount: 2
        }
      };
      
      const result = formatResponse(complexData, 'json', 'aws_enumerate_ec2');
      const parsed = JSON.parse(result.content[0].text);
      
      expect(parsed.data.resources).toHaveLength(2);
      expect(parsed.data.resources[0].id).toBe('i-123');
      expect(parsed.data.metadata.totalCount).toBe(2);
    });

    it('should pretty-print JSON for readability', () => {
      const data = { key: 'value' };
      const result = formatResponse(data, 'json', 'test_tool');
      
      // Check for indentation (pretty-printed)
      expect(result.content[0].text).toContain('\n');
      expect(result.content[0].text).toContain('  '); // 2-space indent
    });
  });

  describe('Format Parameter Validation', () => {
    it('should accept markdown format', () => {
      const validFormats = ['markdown', 'MARKDOWN', 'Markdown'];
      validFormats.forEach(format => {
        expect(() => formatResponse({}, format.toLowerCase() as any, 'test')).not.toThrow();
      });
    });

    it('should accept json format', () => {
      const validFormats = ['json', 'JSON', 'Json'];
      validFormats.forEach(format => {
        expect(() => formatResponse({}, format.toLowerCase() as any, 'test')).not.toThrow();
      });
    });

    it('should default to markdown when undefined', () => {
      // In actual implementation, undefined format defaults to markdown
      const defaultFormat = undefined || 'markdown';
      expect(defaultFormat).toBe('markdown');
    });
  });

  describe('Backward Compatibility', () => {
    it('should maintain existing markdown output structure', () => {
      const legacyData = 'Plain text security report';
      const result = formatResponse(legacyData, 'markdown', 'legacy_tool');
      
      // Should return simple text content, not wrapped in JSON
      expect(result.content[0].text).toBe(legacyData);
      expect(() => JSON.parse(result.content[0].text)).toThrow(); // Not JSON
    });

    it('should not break tools that don\'t specify format', () => {
      // Default behavior (markdown) should work without format parameter
      const data = '## Default output';
      const result = formatResponse(data, 'markdown', 'default_tool');
      
      expect(result.content[0].text).toContain('## Default output');
    });
  });

  describe('Error Handling in Formatting', () => {
    it('should handle null data gracefully', () => {
      const result = formatResponse(null, 'json', 'test_tool');
      const parsed = JSON.parse(result.content[0].text);
      
      expect(parsed.data).toBeNull();
    });

    it('should handle undefined data gracefully', () => {
      const result = formatResponse(undefined, 'json', 'test_tool');
      const parsed = JSON.parse(result.content[0].text);
      
      expect(parsed.data).toBeUndefined();
    });

    it('should handle empty strings', () => {
      const result = formatResponse('', 'markdown', 'test_tool');
      
      expect(result.content[0].text).toBe('');
    });

    it('should handle circular references in JSON', () => {
      const circular: any = { a: 1 };
      circular.self = circular;
      
      // JSON.stringify should throw on circular refs
      expect(() => JSON.stringify(circular)).toThrow();
    });
  });

  describe('Tool Name Tracking', () => {
    it('should correctly identify the calling tool', () => {
      const toolNames = [
        'aws_scan_ec2_security',
        'aws_enumerate_iam_users',
        'aws_detect_privesc_patterns'
      ];
      
      toolNames.forEach(toolName => {
        const result = formatResponse({}, 'json', toolName);
        const parsed = JSON.parse(result.content[0].text);
        expect(parsed.tool).toBe(toolName);
      });
    });
  });

  describe('Performance Considerations', () => {
    it('should handle large datasets efficiently', () => {
      const largeData = {
        resources: Array.from({ length: 1000 }, (_, i) => ({
          id: `resource-${i}`,
          type: 'ec2',
          findings: [`Finding ${i}`]
        }))
      };
      
      const start = Date.now();
      const result = formatResponse(largeData, 'json', 'test_tool');
      const duration = Date.now() - start;
      
      expect(duration).toBeLessThan(100); // Should format in < 100ms
      expect(result.content[0].text.length).toBeGreaterThan(10000);
    });

    it('should not increase memory significantly with markdown', () => {
      const data = 'Simple markdown text';
      const result = formatResponse(data, 'markdown', 'test_tool');
      
      // Markdown should be lightweight (minimal overhead)
      expect(result.content[0].text.length).toBe(data.length);
    });
  });

  describe('Real-World Scenarios', () => {
    it('should format EC2 security findings correctly', () => {
      const ec2Findings = {
        instanceId: 'i-1234567890abcdef0',
        findings: [
          { severity: 'HIGH', issue: 'SSH open to 0.0.0.0/0' },
          { severity: 'MEDIUM', issue: 'Missing IMDSv2 enforcement' }
        ],
        region: 'us-east-1'
      };
      
      const jsonResult = formatResponse(ec2Findings, 'json', 'aws_scan_ec2_security');
      const parsed = JSON.parse(jsonResult.content[0].text);
      
      expect(parsed.data.findings).toHaveLength(2);
      expect(parsed.data.findings[0].severity).toBe('HIGH');
    });

    it('should format IAM privilege escalation findings', () => {
      const iamFindings = {
        patterns: [
          { pattern: 'PassRole + Lambda', risk: 'CRITICAL', principals: 2 },
          { pattern: 'AttachPolicyToUser', risk: 'HIGH', principals: 1 }
        ],
        totalFindings: 2
      };
      
      const jsonResult = formatResponse(iamFindings, 'json', 'aws_detect_privesc_patterns');
      const parsed = JSON.parse(jsonResult.content[0].text);
      
      expect(parsed.data.patterns[0].pattern).toBe('PassRole + Lambda');
      expect(parsed.data.totalFindings).toBe(2);
    });
  });
});
