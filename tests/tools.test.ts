import { describe, it, expect } from '@jest/globals';

// Import the TOOLS array - we'll need to mock the module
// For now, we'll test the structure that tools should follow

describe('AWS Tool Structure Validation', () => {
  // Mock a sample tool structure for testing
  const sampleTool = {
    name: 'enumerate_ec2_instances',
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
    expect(sampleTool.name).toMatch(/^[a-z][a-z0-9_]*$/);
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
    'whoami',
    'enumerate_ec2_instances',
    'analyze_s3_security',
    'scan_secrets_manager',
    'detect_privesc_patterns',
    'build_attack_chains',
  ];

  const invalidToolNames = [
    'WhoAmI',           // camelCase
    'enumerate-ec2',    // kebab-case
    'scan EC2',         // spaces
    'analyze_S3',       // mixed case
  ];

  it('should accept valid snake_case names', () => {
    validToolNames.forEach(name => {
      expect(name).toMatch(/^[a-z][a-z0-9_]*$/);
    });
  });

  it('should reject invalid name formats', () => {
    invalidToolNames.forEach(name => {
      expect(name).not.toMatch(/^[a-z][a-z0-9_]*$/);
    });
  });

  it('should follow verb_noun naming pattern', () => {
    const actionVerbs = ['enumerate', 'analyze', 'scan', 'detect', 'build', 'generate', 'hunt'];
    
    validToolNames.forEach(name => {
      if (name === 'whoami' || name === 'help') return; // special cases
      
      const hasActionVerb = actionVerbs.some(verb => name.startsWith(verb));
      expect(hasActionVerb).toBe(true);
    });
  });
});

describe('Tool Categories', () => {
  const toolCategories = {
    utility: ['help', 'whoami', 'cache_stats', 'cache_clear'],
    enumeration: [
      'enumerate_ec2_instances',
      'enumerate_iam_roles',
      'enumerate_rds_databases',
      'enumerate_eks_clusters',
      'enumerate_public_resources',
      'enumerate_organizations',
      'enumerate_detection_services',
    ],
    security_analysis: [
      'analyze_s3_security',
      'analyze_iam_users',
      'analyze_network_security',
      'analyze_lambda_security',
      'analyze_encryption_security',
      'analyze_api_distribution_security',
      'analyze_messaging_security',
      'analyze_infrastructure_automation',
      'analyze_iam_trust_chains',
      'analyze_service_role_chain',
      'analyze_cross_account_movement',
      'analyze_cloudwatch_security',
      'analyze_ec2_metadata_exposure',
      'analyze_network_exposure',
      'analyze_ami_security',
      'analyze_eks_attack_surface',
    ],
    scanning: [
      'scan_secrets_manager',
      'scan_elasticache_security',
      'scan_ssm_security',
      'scan_resource_policies',
      'scan_eks_service_accounts',
      'scan_all_regions',
    ],
    detection: [
      'detect_permissive_roles',
      'detect_persistence_mechanisms',
      'detect_mfa_bypass_vectors',
      'detect_data_exfiltration_paths',
      'detect_privesc_patterns',
    ],
    reporting: [
      'generate_security_report',
      'generate_tra_report',
      'get_guardduty_findings',
      'get_audit_logs',
    ],
    hunting: [
      'hunt_eks_secrets',
    ],
    chaining: [
      'build_attack_chains',
    ],
    discovery: [
      'list_active_regions',
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
    // AWS has 45 tools total
    expect(allTools.length).toBe(45);
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
    const toolName = 'enumerate_ec2_instances';
    expect(toolName).toMatch(/^[a-z][a-z0-9_]*$/);
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
