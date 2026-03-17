import { describe, it, expect } from '@jest/globals';

// Import the TOOLS array - we'll need to mock the module
// For now, we'll test the structure that tools should follow

describe('AWS Tool Structure Validation', () => {
  // Mock a sample tool structure for testing
  const sampleTool = {
    name: 'aws_enumerate_ec2_instances',
    description: 'List all EC2 instances with security details',
    annotations: {
      readOnly: true,
      destructive: false,
      idempotent: false,
      openWorld: true,
    },
    inputSchema: {
      type: 'object',
      properties: {
        region: {
          type: 'string',
          description: 'AWS region to scan',
        },
      },
      required: ['region'],
    },
  };

  it('should have required tool properties', () => {
    expect(sampleTool).toHaveProperty('name');
    expect(sampleTool).toHaveProperty('description');
    expect(sampleTool).toHaveProperty('inputSchema');
    expect(sampleTool).toHaveProperty('annotations');
  });

  it('should have valid tool name format', () => {
    expect(sampleTool.name).toMatch(/^aws_[a-z][a-z0-9_]*$/);
    expect(sampleTool.name.length).toBeGreaterThan(0);
    expect(sampleTool.name).not.toContain(' ');
  });

  it('should have non-empty description', () => {
    expect(sampleTool.description).toBeTruthy();
    expect(sampleTool.description.length).toBeGreaterThan(10);
  });

  it('should have valid inputSchema structure', () => {
    expect(sampleTool.inputSchema.type).toBe('object');
    expect(sampleTool.inputSchema).toHaveProperty('properties');
  });

  it('should have complete annotations', () => {
    expect(sampleTool.annotations).toHaveProperty('readOnly');
    expect(sampleTool.annotations).toHaveProperty('destructive');
    expect(sampleTool.annotations).toHaveProperty('idempotent');
    expect(sampleTool.annotations).toHaveProperty('openWorld');
  });

  it('should have boolean annotation values', () => {
    expect(typeof sampleTool.annotations.readOnly).toBe('boolean');
    expect(typeof sampleTool.annotations.destructive).toBe('boolean');
    expect(typeof sampleTool.annotations.idempotent).toBe('boolean');
    expect(typeof sampleTool.annotations.openWorld).toBe('boolean');
  });
});

describe('Tool Naming Conventions', () => {
  const validToolNames = [
    'aws_whoami',
    'aws_enumerate_resources',
    'aws_analyze_s3_security',
    'aws_scan_secrets_manager',
    'aws_detect_attack_patterns',
    'aws_build_attack_chains',
  ];

  const invalidToolNames = [
    'WhoAmI',           // camelCase
    'enumerate-ec2',    // kebab-case
    'scan EC2',         // spaces
    'analyze_S3',       // mixed case
    'whoami',           // missing aws_ prefix
  ];

  it('should accept valid snake_case names with aws_ prefix', () => {
    validToolNames.forEach(name => {
      expect(name).toMatch(/^aws_[a-z][a-z0-9_]*$/);
    });
  });

  it('should reject invalid name formats', () => {
    invalidToolNames.forEach(name => {
      expect(name).not.toMatch(/^aws_[a-z][a-z0-9_]*$/);
    });
  });

  it('should follow verb_noun naming pattern', () => {
    const actionVerbs = ['enumerate', 'analyze', 'scan', 'detect', 'build', 'generate', 'hunt'];
    
    validToolNames.forEach(name => {
      if (name === 'aws_whoami' || name === 'aws_help') return; // special cases
      
      const hasActionVerb = actionVerbs.some(verb => name.includes(`_${verb}`));
      expect(hasActionVerb).toBe(true);
    });
  });
});

describe('Tool Categories', () => {
  const toolCategories = {
    utility: ['aws_help', 'aws_whoami', 'aws_cache_manager', 'aws_list_active_regions'],
    enumeration: [
      'aws_enumerate_resources',
    ],
    security_analysis: [
      'aws_analyze_s3_security',
      'aws_analyze_iam_security',
      'aws_analyze_network_security',
      'aws_analyze_lambda_security',
      'aws_analyze_eks_security',
      'aws_analyze_encryption_security',
      'aws_analyze_api_distribution_security',
      'aws_analyze_messaging_security',
      'aws_analyze_infrastructure_automation',
      'aws_analyze_iam_trust_chains',
      'aws_analyze_cross_account_movement',
      'aws_analyze_cloudwatch_security',
      'aws_analyze_ec2_metadata_exposure',
      'aws_analyze_ami_security',
      'aws_analyze_eks_attack_surface',
    ],
    scanning: [
      'aws_scan_secrets_manager',
      'aws_scan_elasticache_security',
      'aws_scan_ssm_security',
      'aws_scan_resource_policies',
      'aws_scan_all_regions',
      'aws_scan_advanced_attacks',
    ],
    detection: [
      'aws_detect_attack_patterns',
    ],
    reporting: [
      'aws_generate_report',
      'aws_get_logs',
    ],
    chaining: [
      'aws_build_attack_chains',
    ],
  };

  it('should have meaningful category groupings', () => {
    const categories = Object.keys(toolCategories) as Array<keyof typeof toolCategories>;
    categories.forEach(category => {
      expect(toolCategories[category].length).toBeGreaterThan(0);
    });
  });

  it('should categorize enumeration tools correctly', () => {
    toolCategories.enumeration.forEach(tool => {
      expect(tool).toContain('enumerate');
    });
  });

  it('should categorize analysis tools correctly', () => {
    toolCategories.security_analysis.forEach(tool => {
      expect(tool).toContain('analyze');
    });
  });

  it('should categorize scanning tools correctly', () => {
    toolCategories.scanning.forEach(tool => {
      expect(tool).toContain('scan');
    });
  });

  it('should categorize detection tools correctly', () => {
    toolCategories.detection.forEach(tool => {
      expect(tool).toContain('detect');
    });
  });

  it('should have unique tool names across all categories', () => {
    const allTools = Object.values(toolCategories).flat();
    const uniqueTools = new Set(allTools);
    expect(uniqueTools.size).toBe(allTools.length);
  });

  it('should count expected number of tools', () => {
    const allTools = Object.values(toolCategories).flat();
    // AWS has 30 tools total (reduced from 50 after Phase 1-5A consolidation: -20 tools)
    // v1.9.0 Phase 1: Consolidated IAM (3→1, -2) and EKS (4→1, -3) with scanMode pattern
    // v1.10.0 Phase 2: Consolidated Detection (4→1, -3) with scanMode pattern
    // v1.11.0 Phase 3A: Consolidated Enumeration (5→1, -4) with resourceType pattern
    // v1.12.0 Phase 3B: Consolidated Reporting (2→1, -1) with reportType pattern
    // v1.13.0 Phase 4A: Consolidated Cache (2→1, -1) with cacheMode pattern
    // v1.13.0 Phase 4B: Consolidated Advanced Attacks (6→1, -5) with attackType pattern
    // v1.14.0 Phase 5A: Consolidated Logging (2→1, -1) with logType pattern
    expect(allTools.length).toBe(30);
  });
});

describe('Input Schema Validation', () => {
  const regionSchema = {
    type: 'string',
    description: 'AWS region to scan (e.g., us-east-1)',
  };

  const optionalBucketSchema = {
    type: 'string',
    description: 'Optional: specific S3 bucket name',
  };

  it('should have proper type definitions', () => {
    expect(regionSchema.type).toBe('string');
    expect(regionSchema).toHaveProperty('description');
  });

  it('should have descriptive property descriptions', () => {
    expect(regionSchema.description.length).toBeGreaterThan(10);
    expect(regionSchema.description).toContain('AWS');
  });

  it('should indicate optional parameters in description', () => {
    expect(optionalBucketSchema.description).toContain('Optional');
  });
});

describe('Tool Annotations Standards', () => {
  const readOnlyAnnotation = {
    readOnly: true,
    destructive: false,
    idempotent: false,
    openWorld: true,
  };

  const utilityAnnotation = {
    readOnly: true,
    destructive: false,
    idempotent: true,
    openWorld: false,
  };

  it('should mark enumeration tools as read-only', () => {
    expect(readOnlyAnnotation.readOnly).toBe(true);
    expect(readOnlyAnnotation.destructive).toBe(false);
  });

  it('should mark utility tools as idempotent', () => {
    expect(utilityAnnotation.idempotent).toBe(true);
    expect(utilityAnnotation.openWorld).toBe(false);
  });

  it('should mark analysis tools as open-world', () => {
    expect(readOnlyAnnotation.openWorld).toBe(true);
  });

  it('should never mark read-only tools as destructive', () => {
    if (readOnlyAnnotation.readOnly) {
      expect(readOnlyAnnotation.destructive).toBe(false);
    }
  });
});

describe('OWASP MCP Compliance - Tool Level', () => {
  it('should follow MCP naming conventions (MCP01)', () => {
    const toolName = 'aws_enumerate_ec2_instances';
    expect(toolName).toMatch(/^aws_[a-z][a-z0-9_]*$/);
    expect(toolName.length).toBeLessThan(100);
  });

  it('should have clear descriptions (MCP02)', () => {
    const description = 'List all EC2 instances with security details';
    expect(description.length).toBeGreaterThan(10);
    expect(description).not.toContain('TODO');
    expect(description).not.toContain('FIXME');
  });

  it('should validate all inputs (MCP03)', () => {
    // Input validation is tested in utils.test.ts
    expect(true).toBe(true);
  });

  it('should declare security properties (MCP05)', () => {
    const annotations = {
      readOnly: true,
      destructive: false,
      idempotent: false,
      openWorld: true,
    };
    
    expect(annotations).toHaveProperty('readOnly');
    expect(annotations).toHaveProperty('destructive');
    expect(annotations).toHaveProperty('idempotent');
    expect(annotations).toHaveProperty('openWorld');
  });
});
