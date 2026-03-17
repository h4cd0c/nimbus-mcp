/**
 * Functional tests for attack detection, advanced scanning, and reporting tools:
 *   aws_detect_attack_patterns, aws_analyze_cross_account_movement,
 *   aws_scan_advanced_attacks, aws_scan_all_regions,
 *   aws_build_attack_chains, aws_generate_report
 */

import { jest, describe, it, expect, beforeAll, afterEach } from '@jest/globals';

const mockSend = jest.fn();
const mockSetRequestHandler = jest.fn();

jest.unstable_mockModule('@modelcontextprotocol/sdk/server/index.js', () => ({
  Server: jest.fn().mockImplementation(() => ({
    setRequestHandler: mockSetRequestHandler,
    connect: jest.fn().mockResolvedValue(undefined),
  })),
}));

jest.unstable_mockModule('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: jest.fn().mockImplementation(() => ({})),
}));

const mkClient = () => jest.fn().mockImplementation(() => ({ send: mockSend }));
const mkCmd    = () => jest.fn().mockImplementation((args: unknown) => args ?? {});

jest.unstable_mockModule('@aws-sdk/client-ec2', () => ({
  EC2Client: mkClient(), DescribeInstancesCommand: mkCmd(), DescribeSecurityGroupsCommand: mkCmd(),
  DescribeVpcsCommand: mkCmd(), DescribeSubnetsCommand: mkCmd(), DescribeImagesCommand: mkCmd(),
  DescribeImageAttributeCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-s3', () => ({
  S3Client: mkClient(), ListBucketsCommand: mkCmd(), GetBucketPolicyCommand: mkCmd(),
  GetBucketEncryptionCommand: mkCmd(), GetPublicAccessBlockCommand: mkCmd(),
  GetBucketAclCommand: mkCmd(), GetBucketVersioningCommand: mkCmd(),
  GetBucketLoggingCommand: mkCmd(), GetBucketPolicyStatusCommand: mkCmd(),
  GetBucketLocationCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-ecr', () => ({
  ECRClient: mkClient(), DescribeRepositoriesCommand: mkCmd(), GetRepositoryPolicyCommand: mkCmd(),
  DescribeImageScanFindingsCommand: mkCmd(), DescribeImagesCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-iam', () => ({
  IAMClient: mkClient(), ListUsersCommand: mkCmd(), ListRolesCommand: mkCmd(),
  ListPoliciesCommand: mkCmd(), GetPolicyVersionCommand: mkCmd(),
  ListAttachedUserPoliciesCommand: mkCmd(), ListAttachedRolePoliciesCommand: mkCmd(),
  ListUserPoliciesCommand: mkCmd(), GetUserPolicyCommand: mkCmd(),
  ListRolePoliciesCommand: mkCmd(), GetRolePolicyCommand: mkCmd(),
  GetRoleCommand: mkCmd(), ListGroupsForUserCommand: mkCmd(),
  ListAttachedGroupPoliciesCommand: mkCmd(), GetPolicyCommand: mkCmd(),
  SimulatePrincipalPolicyCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-rds', () => ({
  RDSClient: mkClient(), DescribeDBInstancesCommand: mkCmd(), DescribeDBClustersCommand: mkCmd(),
  DescribeDBSnapshotsCommand: mkCmd(), DescribeDBSubnetGroupsCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-sts', () => ({
  STSClient: mkClient(), GetCallerIdentityCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-organizations', () => ({
  OrganizationsClient: mkClient(), ListAccountsCommand: mkCmd(),
  DescribeOrganizationCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-eks', () => ({
  EKSClient: mkClient(), ListClustersCommand: mkCmd(), DescribeClusterCommand: mkCmd(),
  ListNodegroupsCommand: mkCmd(), DescribeNodegroupCommand: mkCmd(),
  ListFargateProfilesCommand: mkCmd(), DescribeFargateProfileCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-app-mesh', () => ({
  AppMeshClient: mkClient(), ListMeshesCommand: mkCmd(), DescribeMeshCommand: mkCmd(),
  ListVirtualNodesCommand: mkCmd(), DescribeVirtualNodeCommand: mkCmd(),
  ListVirtualRoutersCommand: mkCmd(), DescribeVirtualRouterCommand: mkCmd(),
  ListVirtualServicesCommand: mkCmd(), DescribeVirtualServiceCommand: mkCmd(),
  ListVirtualGatewaysCommand: mkCmd(), DescribeVirtualGatewayCommand: mkCmd(),
  ListGatewayRoutesCommand: mkCmd(), DescribeGatewayRouteCommand: mkCmd(),
  ListRoutesCommand: mkCmd(), DescribeRouteCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-lambda', () => ({
  LambdaClient: mkClient(), ListFunctionsCommand: mkCmd(), GetFunctionCommand: mkCmd(),
  GetFunctionUrlConfigCommand: mkCmd(), ListEventSourceMappingsCommand: mkCmd(),
  GetFunctionConfigurationCommand: mkCmd(), ListLayerVersionsCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: mkClient(), ListSecretsCommand: mkCmd(), DescribeSecretCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-kms', () => ({
  KMSClient: mkClient(), ListKeysCommand: mkCmd(), DescribeKeyCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-cloudtrail', () => ({
  CloudTrailClient: mkClient(), DescribeTrailsCommand: mkCmd(), GetTrailStatusCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: mkClient(), ListTablesCommand: mkCmd(), DescribeTableCommand: mkCmd(),
  DescribeContinuousBackupsCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-api-gateway', () => ({
  APIGatewayClient: mkClient(), GetRestApisCommand: mkCmd(), GetStagesCommand: mkCmd(),
  GetResourcesCommand: mkCmd(), GetAuthorizersCommand: mkCmd(), GetApiKeysCommand: mkCmd(),
  GetUsagePlansCommand: mkCmd(), GetMethodCommand: mkCmd(), GetRestApiCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-cloudfront', () => ({
  CloudFrontClient: mkClient(), ListDistributionsCommand: mkCmd(), GetDistributionConfigCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-eventbridge', () => ({
  EventBridgeClient: mkClient(), ListRulesCommand: mkCmd(), ListTargetsByRuleCommand: mkCmd(),
  DescribeRuleCommand: mkCmd(), ListEventBusesCommand: mkCmd(), DescribeEventBusCommand: mkCmd(),
  ListArchivesCommand: mkCmd(), DescribeArchiveCommand: mkCmd(),
  DescribeEventSourceCommand: mkCmd(), ListEventSourcesCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-elasticache', () => ({
  ElastiCacheClient: mkClient(), DescribeCacheClustersCommand: mkCmd(),
  DescribeReplicationGroupsCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-guardduty', () => ({
  GuardDutyClient: mkClient(), ListDetectorsCommand: mkCmd(), ListFindingsCommand: mkCmd(),
  GetFindingsCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-sns', () => ({
  SNSClient: mkClient(), ListTopicsCommand: mkCmd(), GetTopicAttributesCommand: mkCmd(),
  ListSubscriptionsByTopicCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-sqs', () => ({
  SQSClient: mkClient(), ListQueuesCommand: mkCmd(), GetQueueAttributesCommand: mkCmd(),
  GetQueueUrlCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-cognito-identity', () => ({
  CognitoIdentityClient: mkClient(), ListIdentityPoolsCommand: mkCmd(),
  DescribeIdentityPoolCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-cognito-identity-provider', () => ({
  CognitoIdentityProviderClient: mkClient(), ListUserPoolsCommand: mkCmd(),
  DescribeUserPoolCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-cloudformation', () => ({
  CloudFormationClient: mkClient(), ListStacksCommand: mkCmd(), DescribeStacksCommand: mkCmd(),
  ListStackResourcesCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-cloudwatch', () => ({
  CloudWatchClient: mkClient(), DescribeAlarmsCommand: mkCmd(),
}));
jest.unstable_mockModule('@aws-sdk/client-sfn', () => ({
  SFNClient: mkClient(), ListStateMachinesCommand: mkCmd(), DescribeStateMachineCommand: mkCmd(),
  DescribeExecutionCommand: mkCmd(), ListExecutionsCommand: mkCmd(),
}));

type ToolResponse = {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
};

let callTool: (name: string, args?: Record<string, unknown>) => Promise<ToolResponse>;

beforeAll(async () => {
  await import('../../src/index.js');
  const handler = mockSetRequestHandler.mock.calls[2][1] as (
    req: { params: { name: string; arguments: Record<string, unknown> } }
  ) => Promise<ToolResponse>;
  callTool = (name, args = {}) => handler({ params: { name, arguments: args } });
}, 60_000);

afterEach(() => { mockSend.mockReset(); });

// ── aws_detect_attack_patterns ────────────────────────────────────────────────

describe('aws_detect_attack_patterns', () => {
  it('detects persistence mechanisms with scanMode=persistence', async () => {
    // detectPersistenceMechanisms uses ListUsersCommand with || [] guard
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_detect_attack_patterns', {
      region: 'us-east-1',
      scanMode: 'persistence',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/Persistence/i);
  });

  it('detects MFA bypass vectors with scanMode=mfa_bypass', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_detect_attack_patterns', {
      region: 'us-east-1',
      scanMode: 'mfa_bypass',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/MFA|bypass/i);
  });

  it('detects privilege escalation with scanMode=privesc', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_detect_attack_patterns', {
      region: 'us-east-1',
      scanMode: 'privesc',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('runs all attack pattern detections with scanMode=all', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_detect_attack_patterns', {
      region: 'us-east-1',
      scanMode: 'all',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/attack pattern|detection/i);
  });

  it('uses default region when none provided', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_detect_attack_patterns', { scanMode: 'persistence' });
    expect(result.isError).toBeFalsy();
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_detect_attack_patterns', {
      region: 'us-east-1',
      scanMode: 'persistence',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_detect_attack_patterns');
  });
});

// ── aws_analyze_cross_account_movement ────────────────────────────────────────

describe('aws_analyze_cross_account_movement', () => {
  it('returns cross-account movement analysis without any params', async () => {
    // trackCrossAccountMovement uses Cognito + IAM, both guarded with || []
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_cross_account_movement', {});
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/cross.account|lateral/i);
  });

  it('does not require a region parameter', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_cross_account_movement');
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_cross_account_movement', { format: 'json' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_cross_account_movement');
  });
});

// ── aws_scan_advanced_attacks ─────────────────────────────────────────────────

describe('aws_scan_advanced_attacks', () => {
  it('scans ECR for poisoning with attackType=ecr', async () => {
    mockSend.mockResolvedValue({ repositories: [] });
    const result = await callTool('aws_scan_advanced_attacks', {
      region: 'us-east-1',
      attackType: 'ecr',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('scans IMDS bypass vulnerabilities with attackType=imds', async () => {
    mockSend.mockResolvedValue({ Reservations: [] });
    const result = await callTool('aws_scan_advanced_attacks', {
      region: 'us-east-1',
      attackType: 'imds',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('scans API Gateway auth with attackType=api_gateway', async () => {
    mockSend.mockResolvedValue({ items: [] });
    const result = await callTool('aws_scan_advanced_attacks', {
      region: 'us-east-1',
      attackType: 'api_gateway',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('runs all attack types with attackType=all', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_scan_advanced_attacks', {
      region: 'us-east-1',
      attackType: 'all',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/Advanced Attack/i);
  });

  it('rejects invalid attackType', async () => {
    const result = await callTool('aws_scan_advanced_attacks', {
      region: 'us-east-1',
      attackType: 'invalid_type',
    });
    expect(result.isError).toBe(true);
  });

  it('uses default region when none provided', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_scan_advanced_attacks', { attackType: 'ecr' });
    expect(result.isError).toBeFalsy();
  });
});

// ── aws_scan_all_regions ──────────────────────────────────────────────────────

describe('aws_scan_all_regions', () => {
  it('scans EC2 across specified regions', async () => {
    mockSend.mockResolvedValue({ Reservations: [] });
    const result = await callTool('aws_scan_all_regions', {
      resourceType: 'ec2',
      regions: 'us-east-1',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/EC2|Multi-Region/i);
  });

  it('scans S3 (global service) with resourceType=s3', async () => {
    mockSend.mockResolvedValue({ Buckets: [] });
    const result = await callTool('aws_scan_all_regions', {
      resourceType: 's3',
      regions: 'us-east-1',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('scans Lambda with a quick scan mode', async () => {
    mockSend.mockResolvedValue({ Functions: [] });
    const result = await callTool('aws_scan_all_regions', {
      resourceType: 'lambda',
      scanMode: 'quick',
      regions: 'us-east-1',
    });
    expect(result.isError).toBeFalsy();
  });

  it('requires resourceType — returns error when omitted', async () => {
    const result = await callTool('aws_scan_all_regions', {});
    expect(result.isError).toBe(true);
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({ Reservations: [] });
    const result = await callTool('aws_scan_all_regions', {
      resourceType: 'ec2',
      regions: 'us-east-1',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_scan_all_regions');
  });
});

// ── aws_build_attack_chains ───────────────────────────────────────────────────

describe('aws_build_attack_chains', () => {
  it('builds attack chains with default parameters', async () => {
    // Uses ListUsersCommand and ListRolesCommand — both use || [] guards
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_build_attack_chains', {});
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/Attack Chain/i);
  });

  it('builds attack chains for a specific region', async () => {
    mockSend.mockResolvedValue({ Users: [], Roles: [] });
    const result = await callTool('aws_build_attack_chains', { region: 'eu-west-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toContain('eu-west-1');
  });

  it('filters by minSeverity', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_build_attack_chains', {
      region: 'us-east-1',
      minSeverity: 'CRITICAL',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toContain('CRITICAL');
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_build_attack_chains', {
      region: 'us-east-1',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_build_attack_chains');
  });
});

// ── aws_generate_report ───────────────────────────────────────────────────────

describe('aws_generate_report', () => {
  it('generates security report with reportType=security', async () => {
    // generateSecurityReport wraps all nested calls in try/catch
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_generate_report', {
      region: 'us-east-1',
      reportType: 'security',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/Security.*Report|Assessment/i);
  });

  it('generates TRA report with reportType=tra', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_generate_report', {
      region: 'us-east-1',
      reportType: 'tra',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('generates combined report with reportType=both', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_generate_report', {
      region: 'us-east-1',
      reportType: 'both',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('uses default region when none provided', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_generate_report', { reportType: 'security' });
    expect(result.isError).toBeFalsy();
  });

  it('accepts optional framework parameter', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_generate_report', {
      region: 'us-east-1',
      reportType: 'tra',
      framework: 'nist',
    });
    expect(result.isError).toBeFalsy();
  });

  it('rejects invalid reportType', async () => {
    const result = await callTool('aws_generate_report', {
      region: 'us-east-1',
      reportType: 'hack_report',
    });
    expect(result.isError).toBe(true);
  });
});
