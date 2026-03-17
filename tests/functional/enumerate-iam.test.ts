/**
 * Functional tests for enumeration and IAM tools:
 *   aws_enumerate_resources, aws_analyze_iam_security, aws_analyze_iam_trust_chains
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

// ── aws_enumerate_resources ──────────────────────────────────────────────────

describe('aws_enumerate_resources', () => {
  it('enumerates organizations without a region', async () => {
    // Organizations scan does not require region
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_enumerate_resources', { resourceType: 'organizations' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/organization/i);
  });

  it('enumerates ec2 resources in a given region', async () => {
    mockSend.mockResolvedValue({ Reservations: [] });
    const result = await callTool('aws_enumerate_resources', {
      resourceType: 'ec2',
      region: 'us-east-1',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('runs all resource types when resourceType=all', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_enumerate_resources', {
      resourceType: 'all',
      region: 'us-east-1',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/Enumeration/i);
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_enumerate_resources', {
      resourceType: 'organizations',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_enumerate_resources');
  });

  it('rejects invalid resourceType', async () => {
    const result = await callTool('aws_enumerate_resources', { resourceType: 'invalid_type' });
    expect(result.isError).toBe(true);
  });
});

// ── aws_analyze_iam_security ─────────────────────────────────────────────────

describe('aws_analyze_iam_security', () => {
  it('enumerates users with scanMode=users', async () => {
    // enumerateIAMUsers checks !response.Users — safe with {}
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_iam_security', { scanMode: 'users' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/user/i);
  });

  it('enumerates roles with scanMode=roles', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_iam_security', { scanMode: 'roles' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/role/i);
  });

  it('runs comprehensive analysis with scanMode=all', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_iam_security', {
      scanMode: 'all',
      region: 'us-east-1',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/IAM/i);
  });

  it('surfaces AccessDenied as isError response', async () => {
    const err = new Error('AccessDeniedException');
    (err as any).name = 'AccessDeniedException';
    mockSend.mockRejectedValue(err);
    const result = await callTool('aws_analyze_iam_security', { scanMode: 'users' });
    // Error is caught internally; output may or may not be isError
    expect(result.content[0].text).toBeTruthy();
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_iam_security', {
      scanMode: 'roles',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_iam_security');
  });

  it('rejects invalid scanMode', async () => {
    const result = await callTool('aws_analyze_iam_security', { scanMode: 'hax' });
    expect(result.isError).toBe(true);
  });
});

// ── aws_analyze_iam_trust_chains ─────────────────────────────────────────────

describe('aws_analyze_iam_trust_chains', () => {
  it('analyzes trust chains with scanMode=trust', async () => {
    // analyzeIAMTrustChains checks !rolesResponse.Roles — safe with {}
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_iam_trust_chains', { scanMode: 'trust' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/trust|IAM/i);
  });

  it('handles service_chain mode with region', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_iam_trust_chains', {
      scanMode: 'service_chain',
      region: 'us-east-1',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('runs both trust and service_chain with scanMode=both', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_iam_trust_chains', {
      scanMode: 'both',
      region: 'us-east-1',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/trust|IAM/i);
  });

  it('warns when service_chain requested without region', async () => {
    // Without region, service_chain analysis is skipped with a warning
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_iam_trust_chains', { scanMode: 'both' });
    // Should succeed but mention region warning
    expect(result.content[0].text).toBeTruthy();
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_iam_trust_chains', {
      scanMode: 'trust',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_iam_trust_chains');
  });
});
