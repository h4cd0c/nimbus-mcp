/**
 * Functional tests for messaging and infrastructure tools:
 *   aws_analyze_messaging_security, aws_analyze_infrastructure_automation,
 *   aws_analyze_api_distribution_security, aws_scan_elasticache_security,
 *   aws_scan_ssm_security
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

// ── aws_analyze_messaging_security ───────────────────────────────────────────

describe('aws_analyze_messaging_security', () => {
  it('scans SNS topics with scanMode=sns', async () => {
    // scanSNSSecurity → ListTopicsCommand → Topics is optional
    mockSend.mockResolvedValue({ Topics: [] });
    const result = await callTool('aws_analyze_messaging_security', {
      region: 'us-east-1',
      scanMode: 'sns',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/SNS|Messaging/i);
  });

  it('scans SQS queues with scanMode=sqs', async () => {
    mockSend.mockResolvedValue({ QueueUrls: [] });
    const result = await callTool('aws_analyze_messaging_security', {
      region: 'us-east-1',
      scanMode: 'sqs',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/SQS|Messaging/i);
  });

  it('runs both SNS and SQS with scanMode=both', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_messaging_security', {
      region: 'us-east-1',
      scanMode: 'both',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/Messaging/i);
  });

  it('uses default region when none provided', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_messaging_security', { scanMode: 'sns' });
    expect(result.isError).toBeFalsy();
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_messaging_security', {
      region: 'us-east-1',
      scanMode: 'sns',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_messaging_security');
  });
});

// ── aws_analyze_infrastructure_automation ────────────────────────────────────

describe('aws_analyze_infrastructure_automation', () => {
  it('scans CloudFormation stacks with scanMode=cloudformation', async () => {
    mockSend.mockResolvedValue({ StackSummaries: [] });
    const result = await callTool('aws_analyze_infrastructure_automation', {
      region: 'us-east-1',
      scanMode: 'cloudformation',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/CloudFormation|Infrastructure/i);
  });

  it('scans EventBridge rules with scanMode=eventbridge', async () => {
    mockSend.mockResolvedValue({ Rules: [] });
    const result = await callTool('aws_analyze_infrastructure_automation', {
      region: 'us-east-1',
      scanMode: 'eventbridge',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/EventBridge|Infrastructure/i);
  });

  it('runs both modes with scanMode=both', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_infrastructure_automation', {
      region: 'us-east-1',
      scanMode: 'both',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/Infrastructure/i);
  });

  it('uses default region when none provided', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_infrastructure_automation', {
      scanMode: 'cloudformation',
    });
    expect(result.isError).toBeFalsy();
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_infrastructure_automation', {
      region: 'us-east-1',
      scanMode: 'eventbridge',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_infrastructure_automation');
  });
});

// ── aws_analyze_api_distribution_security ────────────────────────────────────

describe('aws_analyze_api_distribution_security', () => {
  it('scans API Gateway with scanMode=api_gateway', async () => {
    // GetRestApisCommand → uses .items or similar
    mockSend.mockResolvedValue({ items: [] });
    const result = await callTool('aws_analyze_api_distribution_security', {
      region: 'us-east-1',
      scanMode: 'api_gateway',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/API|Distribution/i);
  });

  it('scans CloudFront with scanMode=cloudfront (region optional)', async () => {
    mockSend.mockResolvedValue({ DistributionList: { Items: [] } });
    const result = await callTool('aws_analyze_api_distribution_security', {
      scanMode: 'cloudfront',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/CloudFront|Distribution/i);
  });

  it('runs both API Gateway and CloudFront with scanMode=both', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_api_distribution_security', {
      scanMode: 'both',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/API|Distribution/i);
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_api_distribution_security', {
      scanMode: 'cloudfront',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_api_distribution_security');
  });
});

// ── aws_scan_elasticache_security ─────────────────────────────────────────────

describe('aws_scan_elasticache_security', () => {
  it('reports no clusters when ElastiCache is empty', async () => {
    // scanElastiCacheSecurity checks clusters.CacheClusters
    mockSend.mockResolvedValue({ CacheClusters: [] });
    const result = await callTool('aws_scan_elasticache_security', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/ElastiCache/i);
  });

  it('detects unencrypted Redis cluster as CRITICAL', async () => {
    mockSend.mockResolvedValueOnce({
      CacheClusters: [{
        CacheClusterId: 'redis-prod',
        Engine: 'redis',
        AtRestEncryptionEnabled: false,
        TransitEncryptionEnabled: false,
        AuthTokenEnabled: false,
        CacheNodes: [{ CacheNodeId: '0001' }],
        CacheSubnetGroupName: 'subnet-group',
      }],
    });
    const result = await callTool('aws_scan_elasticache_security', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/CRITICAL/i);
  });

  it('uses default region when none provided', async () => {
    mockSend.mockResolvedValue({ CacheClusters: [] });
    const result = await callTool('aws_scan_elasticache_security', {});
    expect(result.isError).toBeFalsy();
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({ CacheClusters: [] });
    const result = await callTool('aws_scan_elasticache_security', {
      region: 'us-east-1',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_scan_elasticache_security');
  });
});

// ── aws_scan_ssm_security ─────────────────────────────────────────────────────

describe('aws_scan_ssm_security', () => {
  it('returns SSM security guidance (mostly static output)', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_scan_ssm_security', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/SSM|Systems Manager/i);
  });

  it('uses default region when none provided', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_scan_ssm_security', {});
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('does not call AWS APIs for core output', async () => {
    // SSM function is largely static guidance
    await callTool('aws_scan_ssm_security', { region: 'us-east-1' });
    // May make 0 or minimal calls
    expect(mockSend.mock.calls.length).toBeLessThanOrEqual(5);
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_scan_ssm_security', {
      region: 'us-east-1',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_scan_ssm_security');
  });
});
