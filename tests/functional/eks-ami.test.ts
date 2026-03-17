/**
 * Functional tests for EKS and AMI tools:
 *   aws_analyze_eks_security, aws_analyze_eks_attack_surface, aws_analyze_ami_security
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

// ── aws_analyze_eks_security ─────────────────────────────────────────────────

describe('aws_analyze_eks_security', () => {
  it('lists clusters with scanMode=clusters (no clusterName needed)', async () => {
    // enumerateEKSClusters: checks !listResponse.clusters → safe with {}
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_eks_security', {
      region: 'us-east-1',
      scanMode: 'clusters',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/EKS|cluster/i);
  });

  it('runs all-mode analysis without clusterName (skips IRSA sections)', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_eks_security', {
      region: 'us-east-1',
      scanMode: 'all',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/EKS/i);
  });

  it('requires clusterName for irsa scanMode', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_eks_security', {
      region: 'us-east-1',
      scanMode: 'irsa',
      // no clusterName
    });
    // Should return error since clusterName is required for irsa mode
    expect(result.isError).toBe(true);
  });

  it('uses default region when none provided', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_eks_security', { scanMode: 'clusters' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_eks_security', {
      region: 'us-east-1',
      scanMode: 'clusters',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_eks_security');
  });
});

// ── aws_analyze_eks_attack_surface ───────────────────────────────────────────

describe('aws_analyze_eks_attack_surface', () => {
  it('returns attack surface summary when no clusters found', async () => {
    // ListClustersCommand returns {} → clusters = [] → "No EKS clusters found"
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_eks_attack_surface', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/EKS|cluster/i);
  });

  it('analyzes a named cluster directly (skips ListClusters)', async () => {
    // When clusterName is given, goes straight to DescribeClusterCommand
    mockSend.mockResolvedValueOnce({
      cluster: {
        name: 'test-cluster',
        version: '1.28',
        status: 'ACTIVE',
        endpoint: 'https://test.example.com',
        resourcesVpcConfig: { endpointPublicAccess: false, endpointPrivateAccess: true },
        logging: { clusterLogging: [] },
        encryptionConfig: [],
      },
    });
    const result = await callTool('aws_analyze_eks_attack_surface', {
      region: 'us-east-1',
      clusterName: 'testCluster1',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/EKS|Attack Surface/i);
  });

  it('uses default region when not provided', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_eks_attack_surface', {});
    expect(result.isError).toBeFalsy();
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_eks_attack_surface', {
      region: 'us-east-1',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_eks_attack_surface');
  });
});

// ── aws_analyze_ami_security ─────────────────────────────────────────────────

describe('aws_analyze_ami_security', () => {
  it('reports no custom AMIs when account has none', async () => {
    // STS GetCallerIdentity → Images list from EC2
    mockSend
      .mockResolvedValueOnce({ Account: '123456789012' })  // GetCallerIdentityCommand
      .mockResolvedValueOnce({ Images: [] });               // DescribeImagesCommand
    const result = await callTool('aws_analyze_ami_security', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/AMI|No custom/i);
  });

  it('detects public AMI as CRITICAL finding', async () => {
    mockSend
      .mockResolvedValueOnce({ Account: '123456789012' })
      .mockResolvedValueOnce({
        Images: [{
          ImageId: 'ami-12345678',
          Name: 'my-test-ami',
          Public: true,
          CreationDate: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString(),
          BlockDeviceMappings: [{ Ebs: { Encrypted: false } }],
        }],
      });
    const result = await callTool('aws_analyze_ami_security', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/CRITICAL|public/i);
  });

  it('accepts includeAwsManaged flag', async () => {
    mockSend
      .mockResolvedValueOnce({ Account: '123456789012' })
      .mockResolvedValueOnce({ Images: [] });
    const result = await callTool('aws_analyze_ami_security', {
      region: 'us-east-1',
      includeAwsManaged: true,
    });
    expect(result.isError).toBeFalsy();
  });

  it('uses default region when none provided', async () => {
    mockSend.mockResolvedValue({});
    const result = await callTool('aws_analyze_ami_security', {});
    expect(result.isError).toBeFalsy();
  });

  it('returns JSON envelope with format=json', async () => {
    mockSend
      .mockResolvedValueOnce({ Account: '123456789012' })
      .mockResolvedValueOnce({ Images: [] });
    const result = await callTool('aws_analyze_ami_security', {
      region: 'us-east-1',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_ami_security');
  });
});
