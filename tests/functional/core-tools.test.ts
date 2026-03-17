/**
 * Functional tests for core AWS tools: aws_help, aws_whoami, aws_cache_manager,
 * aws_list_active_regions, aws_enumerate_resources (basic), plus input validation
 * and error-handling behaviours.
 *
 * Architecture:
 *   - All AWS SDK modules are mocked before index.ts is dynamically imported.
 *   - The MCP Server class is mocked to capture the CallTool request handler.
 *   - mockSend is the shared send() implementation injected into every client.
 *
 * Handler capture order (fixed in index.ts):
 *   calls[0] → ListToolsRequestSchema
 *   calls[1] → CompleteRequestSchema
 *   calls[2] → CallToolRequestSchema  ← the one we use
 */

import { jest, describe, it, expect, beforeAll, afterEach } from '@jest/globals';

// ── Shared mock primitives ──────────────────────────────────────────────────
const mockSend = jest.fn();
const mockSetRequestHandler = jest.fn();

// ── MCP SDK mocks (must be registered BEFORE dynamic import of index.ts) ────

jest.unstable_mockModule('@modelcontextprotocol/sdk/server/index.js', () => ({
  Server: jest.fn().mockImplementation(() => ({
    setRequestHandler: mockSetRequestHandler,
    connect: jest.fn().mockResolvedValue(undefined),
  })),
}));

jest.unstable_mockModule('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: jest.fn().mockImplementation(() => ({})),
}));

// ── AWS SDK mocks ────────────────────────────────────────────────────────────
// Each Client returns { send: mockSend }; Command constructors are no-ops.

const mkClient = () => jest.fn().mockImplementation(() => ({ send: mockSend }));
const mkCmd    = () => jest.fn().mockImplementation((args: unknown) => args ?? {});

jest.unstable_mockModule('@aws-sdk/client-ec2', () => ({
  EC2Client: mkClient(),
  DescribeInstancesCommand: mkCmd(),
  DescribeSecurityGroupsCommand: mkCmd(),
  DescribeVpcsCommand: mkCmd(),
  DescribeSubnetsCommand: mkCmd(),
  DescribeImagesCommand: mkCmd(),
  DescribeImageAttributeCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-s3', () => ({
  S3Client: mkClient(),
  ListBucketsCommand: mkCmd(),
  GetBucketPolicyCommand: mkCmd(),
  GetBucketEncryptionCommand: mkCmd(),
  GetPublicAccessBlockCommand: mkCmd(),
  GetBucketAclCommand: mkCmd(),
  GetBucketVersioningCommand: mkCmd(),
  GetBucketLoggingCommand: mkCmd(),
  GetBucketPolicyStatusCommand: mkCmd(),
  GetBucketLocationCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-ecr', () => ({
  ECRClient: mkClient(),
  DescribeRepositoriesCommand: mkCmd(),
  GetRepositoryPolicyCommand: mkCmd(),
  DescribeImageScanFindingsCommand: mkCmd(),
  DescribeImagesCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-iam', () => ({
  IAMClient: mkClient(),
  ListUsersCommand: mkCmd(),
  ListRolesCommand: mkCmd(),
  ListPoliciesCommand: mkCmd(),
  GetPolicyVersionCommand: mkCmd(),
  ListAttachedUserPoliciesCommand: mkCmd(),
  ListAttachedRolePoliciesCommand: mkCmd(),
  ListUserPoliciesCommand: mkCmd(),
  GetUserPolicyCommand: mkCmd(),
  ListRolePoliciesCommand: mkCmd(),
  GetRolePolicyCommand: mkCmd(),
  GetRoleCommand: mkCmd(),
  ListGroupsForUserCommand: mkCmd(),
  ListAttachedGroupPoliciesCommand: mkCmd(),
  GetPolicyCommand: mkCmd(),
  SimulatePrincipalPolicyCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-rds', () => ({
  RDSClient: mkClient(),
  DescribeDBInstancesCommand: mkCmd(),
  DescribeDBClustersCommand: mkCmd(),
  DescribeDBSnapshotsCommand: mkCmd(),
  DescribeDBSubnetGroupsCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-sts', () => ({
  STSClient: mkClient(),
  GetCallerIdentityCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-organizations', () => ({
  OrganizationsClient: mkClient(),
  ListAccountsCommand: mkCmd(),
  DescribeOrganizationCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-eks', () => ({
  EKSClient: mkClient(),
  ListClustersCommand: mkCmd(),
  DescribeClusterCommand: mkCmd(),
  ListNodegroupsCommand: mkCmd(),
  DescribeNodegroupCommand: mkCmd(),
  ListFargateProfilesCommand: mkCmd(),
  DescribeFargateProfileCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-app-mesh', () => ({
  AppMeshClient: mkClient(),
  ListMeshesCommand: mkCmd(),
  DescribeMeshCommand: mkCmd(),
  ListVirtualNodesCommand: mkCmd(),
  DescribeVirtualNodeCommand: mkCmd(),
  ListVirtualRoutersCommand: mkCmd(),
  DescribeVirtualRouterCommand: mkCmd(),
  ListVirtualServicesCommand: mkCmd(),
  DescribeVirtualServiceCommand: mkCmd(),
  ListVirtualGatewaysCommand: mkCmd(),
  DescribeVirtualGatewayCommand: mkCmd(),
  ListGatewayRoutesCommand: mkCmd(),
  DescribeGatewayRouteCommand: mkCmd(),
  ListRoutesCommand: mkCmd(),
  DescribeRouteCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-lambda', () => ({
  LambdaClient: mkClient(),
  ListFunctionsCommand: mkCmd(),
  GetFunctionCommand: mkCmd(),
  GetFunctionUrlConfigCommand: mkCmd(),
  ListEventSourceMappingsCommand: mkCmd(),
  GetFunctionConfigurationCommand: mkCmd(),
  ListLayerVersionsCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-secrets-manager', () => ({
  SecretsManagerClient: mkClient(),
  ListSecretsCommand: mkCmd(),
  DescribeSecretCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-kms', () => ({
  KMSClient: mkClient(),
  ListKeysCommand: mkCmd(),
  DescribeKeyCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-cloudtrail', () => ({
  CloudTrailClient: mkClient(),
  DescribeTrailsCommand: mkCmd(),
  GetTrailStatusCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: mkClient(),
  ListTablesCommand: mkCmd(),
  DescribeTableCommand: mkCmd(),
  DescribeContinuousBackupsCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-api-gateway', () => ({
  APIGatewayClient: mkClient(),
  GetRestApisCommand: mkCmd(),
  GetStagesCommand: mkCmd(),
  GetResourcesCommand: mkCmd(),
  GetAuthorizersCommand: mkCmd(),
  GetApiKeysCommand: mkCmd(),
  GetUsagePlansCommand: mkCmd(),
  GetMethodCommand: mkCmd(),
  GetRestApiCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-cloudfront', () => ({
  CloudFrontClient: mkClient(),
  ListDistributionsCommand: mkCmd(),
  GetDistributionConfigCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-eventbridge', () => ({
  EventBridgeClient: mkClient(),
  ListRulesCommand: mkCmd(),
  ListTargetsByRuleCommand: mkCmd(),
  DescribeRuleCommand: mkCmd(),
  ListEventBusesCommand: mkCmd(),
  DescribeEventBusCommand: mkCmd(),
  ListArchivesCommand: mkCmd(),
  DescribeArchiveCommand: mkCmd(),
  DescribeEventSourceCommand: mkCmd(),
  ListEventSourcesCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-elasticache', () => ({
  ElastiCacheClient: mkClient(),
  DescribeCacheClustersCommand: mkCmd(),
  DescribeReplicationGroupsCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-guardduty', () => ({
  GuardDutyClient: mkClient(),
  ListDetectorsCommand: mkCmd(),
  ListFindingsCommand: mkCmd(),
  GetFindingsCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-sns', () => ({
  SNSClient: mkClient(),
  ListTopicsCommand: mkCmd(),
  GetTopicAttributesCommand: mkCmd(),
  ListSubscriptionsByTopicCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-sqs', () => ({
  SQSClient: mkClient(),
  ListQueuesCommand: mkCmd(),
  GetQueueAttributesCommand: mkCmd(),
  GetQueueUrlCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-cognito-identity', () => ({
  CognitoIdentityClient: mkClient(),
  ListIdentityPoolsCommand: mkCmd(),
  DescribeIdentityPoolCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-cognito-identity-provider', () => ({
  CognitoIdentityProviderClient: mkClient(),
  ListUserPoolsCommand: mkCmd(),
  DescribeUserPoolCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-cloudformation', () => ({
  CloudFormationClient: mkClient(),
  ListStacksCommand: mkCmd(),
  DescribeStacksCommand: mkCmd(),
  ListStackResourcesCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-cloudwatch', () => ({
  CloudWatchClient: mkClient(),
  DescribeAlarmsCommand: mkCmd(),
}));

jest.unstable_mockModule('@aws-sdk/client-sfn', () => ({
  SFNClient: mkClient(),
  ListStateMachinesCommand: mkCmd(),
  DescribeStateMachineCommand: mkCmd(),
  DescribeExecutionCommand: mkCmd(),
  ListExecutionsCommand: mkCmd(),
}));

// ── Load index.ts after mocks are registered ────────────────────────────────

type ToolResponse = {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
};

let callTool: (name: string, args?: Record<string, unknown>) => Promise<ToolResponse>;

beforeAll(async () => {
  // Dynamic import triggers module-level code in index.ts.
  // main() is harmless because StdioServerTransport and server.connect are mocked.
  await import('../../src/index.js');

  // Third setRequestHandler call (index 2) is for CallToolRequestSchema
  const handler = mockSetRequestHandler.mock.calls[2][1] as (
    req: { params: { name: string; arguments: Record<string, unknown> } }
  ) => Promise<ToolResponse>;

  callTool = (name: string, args: Record<string, unknown> = {}) =>
    handler({ params: { name, arguments: args } });
}, 60_000);

afterEach(() => {
  mockSend.mockReset();
});

// ── aws_help ─────────────────────────────────────────────────────────────────

describe('aws_help', () => {
  it('returns a non-empty markdown help text', async () => {
    const result = await callTool('aws_help');
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toContain('AWS');
    expect(result.content[0].text.length).toBeGreaterThan(100);
  });

  it('does not make any AWS API calls', async () => {
    await callTool('aws_help');
    expect(mockSend).not.toHaveBeenCalled();
  });

  it('returns JSON envelope when format=json', async () => {
    const result = await callTool('aws_help', { format: 'json' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_help');
    expect(parsed).toHaveProperty('format', 'json');
    expect(parsed).toHaveProperty('data');
  });
});

// ── aws_whoami ────────────────────────────────────────────────────────────────

describe('aws_whoami', () => {
  it('returns caller identity information', async () => {
    mockSend.mockResolvedValueOnce({
      UserId: 'AIDABC123XYZ',
      Account: '123456789012',
      Arn: 'arn:aws:iam::123456789012:user/pentest-user',
    });

    const result = await callTool('aws_whoami', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    const text = result.content[0].text;
    expect(text).toContain('123456789012');
    expect(text).toContain('pentest-user');
    expect(text).toContain('AIDABC123XYZ');
  });

  it('works without a region parameter (uses default)', async () => {
    mockSend.mockResolvedValueOnce({
      UserId: 'AROAEXAMPLE',
      Account: '999888777666',
      Arn: 'arn:aws:sts::999888777666:assumed-role/TestRole/session',
    });

    const result = await callTool('aws_whoami');
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toContain('999888777666');
  });

  it('returns JSON envelope when format=json', async () => {
    mockSend.mockResolvedValueOnce({
      UserId: 'AIDABC123',
      Account: '111222333444',
      Arn: 'arn:aws:iam::111222333444:user/test',
    });

    const result = await callTool('aws_whoami', { format: 'json' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_whoami');
    expect(parsed.format).toBe('json');
  });

  it('surfaces AWS error as error response (not unhandled throw)', async () => {
    const err = new Error('AccessDeniedException: User is not authorized');
    (err as any).name = 'AccessDeniedException';
    mockSend.mockRejectedValueOnce(err);

    const result = await callTool('aws_whoami', { region: 'us-east-1' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/access|denied|error/i);
  });

  it('rejects an invalid region', async () => {
    const result = await callTool('aws_whoami', { region: 'not-a-region!' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/region|invalid/i);
  });
});

// ── aws_cache_manager ─────────────────────────────────────────────────────────

describe('aws_cache_manager', () => {
  it('returns cache stats without making AWS calls', async () => {
    const result = await callTool('aws_cache_manager', { cacheMode: 'stats' });
    expect(result.isError).toBeFalsy();
    expect(mockSend).not.toHaveBeenCalled();
    expect(result.content[0].text).toMatch(/cache/i);
  });

  it('clears cache and reports count', async () => {
    const result = await callTool('aws_cache_manager', { cacheMode: 'clear' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/cleared/i);
  });

  it('supports both mode (stats then clear)', async () => {
    const result = await callTool('aws_cache_manager', { cacheMode: 'both' });
    expect(result.isError).toBeFalsy();
    // A "both" response should contain cache-related text
    expect(result.content[0].text).toBeTruthy();
  });

  it('returns JSON envelope when format=json', async () => {
    const result = await callTool('aws_cache_manager', { cacheMode: 'stats', format: 'json' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_cache_manager');
  });

  it('rejects unknown cacheMode with error response', async () => {
    const result = await callTool('aws_cache_manager', { cacheMode: 'destroy_everything' });
    expect(result.isError).toBe(true);
  });
});

// ── aws_list_active_regions ──────────────────────────────────────────────────

describe('aws_list_active_regions', () => {
  it('lists regions with resources when AWS returns instances', async () => {
    // aws_list_active_regions scans configured regions by calling EC2/Lambda/RDS
    // Mock enough responses for a couple of regions (resolves empty for most)
    mockSend.mockResolvedValue({ Reservations: [], Functions: [], DBInstances: [] });

    const result = await callTool('aws_list_active_regions', { regions: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('calls AWS APIs when scanning real regions', async () => {
    mockSend.mockResolvedValue({ Reservations: [], Functions: [], DBInstances: [] });

    await callTool('aws_list_active_regions', { regions: 'us-east-1,eu-west-1' });
    expect(mockSend).toHaveBeenCalled();
  });

  it('accepts scanMode=common without error', async () => {
    mockSend.mockResolvedValue({ Reservations: [], Functions: [], DBInstances: [] });

    const result = await callTool('aws_list_active_regions', { scanMode: 'common' });
    expect(result.content[0].text).toBeTruthy();
  });
});

// ── Input validation across tools ────────────────────────────────────────────

describe('Input validation', () => {
  it('aws_analyze_network_security: uses default region when none provided', async () => {
    // region defaults to us-east-1; mock returns empty so tool succeeds
    mockSend.mockResolvedValue({ Vpcs: [], SecurityGroups: [], Subnets: [] });
    const result = await callTool('aws_analyze_network_security', {});
    expect(result.isError).toBeFalsy();
  });

  it('aws_scan_secrets_manager: uses default region when none provided', async () => {
    mockSend.mockResolvedValueOnce({ SecretList: [] });
    const result = await callTool('aws_scan_secrets_manager', {});
    expect(result.isError).toBeFalsy();
  });

  it('aws_analyze_lambda_security: uses default region when none provided', async () => {
    mockSend.mockResolvedValueOnce({ Functions: [] });
    const result = await callTool('aws_analyze_lambda_security', {});
    expect(result.isError).toBeFalsy();
  });

  it('aws_analyze_network_security: path traversal in region rejected', async () => {
    const result = await callTool('aws_analyze_network_security', {
      region: '../../etc/passwd',
    });
    expect(result.isError).toBe(true);
  });

  it('unknown tool name: returns isError with unknown-tool message', async () => {
    const result = await callTool('aws_nonexistent_tool_xyz');
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/unknown tool/i);
  });
});

// ── Error handling (AWS SDK failures) ────────────────────────────────────────

describe('AWS error handling', () => {
  it('aws_analyze_cloudwatch_security: handles AccessDenied gracefully', async () => {
    const err = new Error('AccessDeniedException');
    (err as any).name = 'AccessDeniedException';
    mockSend.mockRejectedValue(err);

    const result = await callTool('aws_analyze_cloudwatch_security', { region: 'us-east-1' });
    // cloudwatch security catches errors internally and returns content (not isError)
    expect(result.content[0].text.length).toBeGreaterThan(0);
  });

  it('error response includes human-readable message', async () => {
    mockSend.mockRejectedValue(new Error('SomeAWSError: something bad happened'));

    const result = await callTool('aws_analyze_cloudwatch_security', { region: 'us-east-1' });
    expect(result.content[0].text.length).toBeGreaterThan(0);
    expect(typeof result.content[0].text).toBe('string');
  });

  it('error response in JSON format is valid JSON', async () => {
    mockSend.mockRejectedValue(new Error('TestError'));
    const result = await callTool('aws_analyze_cloudwatch_security', {
      region: 'us-east-1',
      format: 'json',
    });
    // cloudwatch security catches errors gracefully; format=json still yields parseable JSON
    expect(() => JSON.parse(result.content[0].text)).not.toThrow();
  });
});
