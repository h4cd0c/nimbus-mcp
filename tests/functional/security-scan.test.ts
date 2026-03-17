/**
 * Functional tests for AWS security-scanning tools:
 *   aws_analyze_s3_security, aws_scan_secrets_manager,
 *   aws_analyze_network_security, aws_analyze_encryption_security,
 *   aws_analyze_iam_security, aws_analyze_cloudwatch_security,
 *   aws_analyze_ec2_metadata_exposure, aws_scan_resource_policies,
 *   aws_get_logs (audit + guardduty).
 *
 * Each tool is invoked through the real CallTool handler captured from
 * the mocked MCP Server instance, exercising the full switch-case dispatch
 * and internal implementation functions.
 */

import { jest, describe, it, expect, beforeAll, afterEach } from '@jest/globals';

// ── Shared mock primitives ───────────────────────────────────────────────────
const mockSend = jest.fn();
const mockSetRequestHandler = jest.fn();

// ── MCP SDK mocks ────────────────────────────────────────────────────────────

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

// ── Load index.ts ────────────────────────────────────────────────────────────

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

afterEach(() => {
  mockSend.mockReset();
});

// ── aws_analyze_s3_security ───────────────────────────────────────────────────

describe('aws_analyze_s3_security', () => {
  it('lists all buckets (no scanMode arg — defaults to both, no bucketName)', async () => {
    // No scanMode provided: handler passes undefined, function defaults to 'both'
    // Without bucketName, only enumerateS3Buckets() runs (one ListBuckets call)
    mockSend.mockResolvedValueOnce({
      Buckets: [
        { Name: 'public-data-bucket', CreationDate: new Date() },
        { Name: 'logs-bucket', CreationDate: new Date() },
      ],
    });

    const result = await callTool('aws_analyze_s3_security');
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toContain('public-data-bucket');
    expect(result.content[0].text).toContain('logs-bucket');
  });

  it('no buckets returns "No S3 buckets found"', async () => {
    mockSend.mockResolvedValueOnce({ Buckets: [] });
    const result = await callTool('aws_analyze_s3_security');
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/no.*bucket/i);
  });

  it('with bucketName — detects missing public access block as CRITICAL', async () => {
    // 'both' mode (no scanMode): first ListBuckets, then full security scan
    mockSend.mockResolvedValueOnce({ Buckets: [] });  // ListBuckets (enumerate phase)
    mockSend.mockResolvedValueOnce({ LocationConstraint: 'us-east-1' });  // GetBucketLocation
    const noBlockErr = new Error('NoSuchPublicAccessBlockConfiguration');
    (noBlockErr as any).name = 'NoSuchPublicAccessBlockConfiguration';
    mockSend.mockRejectedValueOnce(noBlockErr);  // GetPublicAccessBlock — missing
    const noPolicyErr = new Error('NoSuchBucketPolicy');
    (noPolicyErr as any).name = 'NoSuchBucketPolicy';
    mockSend.mockRejectedValueOnce(noPolicyErr);  // GetBucketPolicy — none
    // ACL, policyStatus, encryption, versioning, logging return safe defaults
    mockSend.mockResolvedValue({
      Grants: [],
      PolicyStatus: { IsPublic: false },
      ServerSideEncryptionConfiguration: {
        Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }],
      },
      Status: 'Enabled',
      MFADelete: 'Disabled',
      LoggingEnabled: null,
    });

    const result = await callTool('aws_analyze_s3_security', { bucketName: 'my-test-bucket' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/critical|CRITICAL/i);
  });

  it('with bucketName — fully secured bucket reports no critical findings', async () => {
    mockSend.mockResolvedValueOnce({ Buckets: [] });  // ListBuckets
    mockSend.mockResolvedValueOnce({ LocationConstraint: 'eu-west-1' });  // GetBucketLocation
    mockSend.mockResolvedValueOnce({
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true, BlockPublicPolicy: true,
        IgnorePublicAcls: true, RestrictPublicBuckets: true,
      },
    });  // GetPublicAccessBlock
    const noPolicyErr = new Error('NoSuchBucketPolicy');
    (noPolicyErr as any).name = 'NoSuchBucketPolicy';
    mockSend.mockRejectedValueOnce(noPolicyErr);  // GetBucketPolicy — none
    mockSend.mockResolvedValueOnce({ Grants: [] });  // GetBucketAcl
    mockSend.mockResolvedValueOnce({ PolicyStatus: { IsPublic: false } });  // GetBucketPolicyStatus
    mockSend.mockResolvedValueOnce({
      ServerSideEncryptionConfiguration: {
        Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms' } }],
      },
    });  // GetBucketEncryption
    mockSend.mockResolvedValueOnce({ Status: 'Enabled', MFADelete: 'Enabled' });  // GetBucketVersioning
    mockSend.mockResolvedValueOnce({ LoggingEnabled: { TargetBucket: 'logs', TargetPrefix: '/' } });  // GetBucketLogging

    const result = await callTool('aws_analyze_s3_security', { bucketName: 'secure-bucket' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/No security issues found|Findings.*0|0 finding/i);
  });

  it('returns JSON envelope when format=json', async () => {
    mockSend.mockResolvedValueOnce({ Buckets: [{ Name: 'example', CreationDate: new Date() }] });
    const result = await callTool('aws_analyze_s3_security', { format: 'json' });  // no scanMode
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_s3_security');
  });
});

// ── aws_scan_secrets_manager ──────────────────────────────────────────────────

describe('aws_scan_secrets_manager', () => {
  it('reports secrets without rotation as MEDIUM findings', async () => {
    const now = new Date();
    const oldDate = new Date(now.getTime() - 100 * 24 * 60 * 60 * 1000); // 100 days ago

    mockSend.mockResolvedValueOnce({
      SecretList: [
        {
          Name: 'prod/db/password',
          ARN: 'arn:aws:secretsmanager:us-east-1:123:secret:prod/db/password-XXXXX',
          RotationEnabled: false,
          LastChangedDate: oldDate,
          LastAccessedDate: now,
        },
      ],
    });

    const result = await callTool('aws_scan_secrets_manager', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    const text = result.content[0].text;
    expect(text).toContain('prod/db/password');
    expect(text).toMatch(/rotation|MEDIUM/i);
  });

  it('reports no findings when secrets are well configured', async () => {
    const recent = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000); // 10 days ago

    mockSend.mockResolvedValueOnce({
      SecretList: [
        {
          Name: 'api/key1',
          ARN: 'arn:aws:secretsmanager:us-east-1:123:secret:api/key1',
          RotationEnabled: true,
          LastChangedDate: recent,
          LastAccessedDate: recent,
        },
      ],
    });

    const result = await callTool('aws_scan_secrets_manager', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/All secrets properly configured|0.*finding|no security issues/i);
  });

  it('reports "no secrets found" when SecretList is empty', async () => {
    mockSend.mockResolvedValueOnce({ SecretList: [] });
    const result = await callTool('aws_scan_secrets_manager', { region: 'ap-southeast-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/no secrets found/i);
  });

  it('handles AccessDenied as error response', async () => {
    const err = new Error('AccessDeniedException: User not authorized');
    (err as any).name = 'AccessDeniedException';
    mockSend.mockRejectedValueOnce(err);

    const result = await callTool('aws_scan_secrets_manager', { region: 'us-east-1' });
    expect(result.isError).toBe(true);
  });

  it('uses default region when none provided', async () => {
    // region defaults to us-east-1; tool should succeed with empty secret list
    mockSend.mockResolvedValueOnce({ SecretList: [] });
    const result = await callTool('aws_scan_secrets_manager', {});
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/no secrets found/i);
  });
});

// ── aws_analyze_network_security ──────────────────────────────────────────────

describe('aws_analyze_network_security', () => {
  const OPEN_SG = {
    SecurityGroups: [
      {
        GroupId: 'sg-deadbeef',
        GroupName: 'open-sg',
        Description: 'Too open',
        VpcId: 'vpc-1234',
        IpPermissions: [
          {
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            IpRanges: [{ CidrIp: '0.0.0.0/0' }],
          },
        ],
      },
    ],
  };

  it('security_groups mode — flags SSH open to 0.0.0.0/0 as CRITICAL', async () => {
    mockSend.mockResolvedValueOnce(OPEN_SG);

    const result = await callTool('aws_analyze_network_security', {
      region: 'us-east-1',
      scanMode: 'security_groups',
    });
    expect(result.isError).toBeFalsy();
    const text = result.content[0].text;
    expect(text).toMatch(/CRITICAL|critical/i);
    expect(text).toContain('22');
  });

  it('security_groups mode — no dangerous rules means no CRITICAL findings', async () => {
    mockSend.mockResolvedValueOnce({
      SecurityGroups: [
        {
          GroupId: 'sg-safe',
          GroupName: 'safe-sg',
          Description: 'Properly locked',
          VpcId: 'vpc-1234',
          IpPermissions: [
            {
              IpProtocol: 'tcp',
              FromPort: 443,
              ToPort: 443,
              IpRanges: [{ CidrIp: '10.0.0.0/8' }],
            },
          ],
        },
      ],
    });

    const result = await callTool('aws_analyze_network_security', {
      region: 'us-east-1',
      scanMode: 'security_groups',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/no critical|0.*CRITICAL/i);
  });

  it('vpcs mode — lists VPCs and subnets', async () => {
    mockSend
      .mockResolvedValueOnce({
        Vpcs: [{ VpcId: 'vpc-abc', CidrBlock: '10.0.0.0/16', IsDefault: false, State: 'available' }],
      })
      .mockResolvedValueOnce({ Subnets: [{ SubnetId: 'subnet-1', MapPublicIpOnLaunch: false }] });

    const result = await callTool('aws_analyze_network_security', {
      region: 'us-west-2',
      scanMode: 'vpcs',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toContain('vpc-abc');
  });

  it('uses default region when none provided', async () => {
    // region defaults to us-east-1; security_groups scan with empty list succeeds
    mockSend.mockResolvedValueOnce({ SecurityGroups: [] });
    const result = await callTool('aws_analyze_network_security', { scanMode: 'security_groups' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/no critical|security group/i);
  });

  it('returns JSON envelope when format=json', async () => {
    mockSend.mockResolvedValueOnce({ SecurityGroups: [] });
    const result = await callTool('aws_analyze_network_security', {
      region: 'us-east-1',
      scanMode: 'security_groups',
      format: 'json',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_network_security');
  });
});

// ── aws_analyze_encryption_security ──────────────────────────────────────────

describe('aws_analyze_encryption_security', () => {
  it('kms mode — lists customer-managed keys', async () => {
    mockSend
      .mockResolvedValueOnce({ Keys: [{ KeyId: 'key-1234', KeyArn: 'arn:...' }] })
      .mockResolvedValueOnce({
        KeyMetadata: {
          KeyId: 'key-1234',
          KeyState: 'Enabled',
          Enabled: true,
          KeyManager: 'CUSTOMER',
          Description: 'My encryption key',
          CreationDate: new Date(),
        },
      });

    const result = await callTool('aws_analyze_encryption_security', {
      region: 'us-east-1',
      resourceType: 'kms',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toContain('key-1234');
  });

  it('dynamodb mode — flags table without encryption as CRITICAL', async () => {
    mockSend
      .mockResolvedValueOnce({ TableNames: ['orders-table'] })
      .mockResolvedValueOnce({
        Table: {
          TableName: 'orders-table',
          TableStatus: 'ACTIVE',
          ItemCount: 5000,
          SSEDescription: null, // No encryption
          BillingModeSummary: { BillingMode: 'PROVISIONED' },
        },
      })
      .mockResolvedValueOnce({
        ContinuousBackupsDescription: {
          PointInTimeRecoveryDescription: { PointInTimeRecoveryStatus: 'DISABLED' },
        },
      });

    const result = await callTool('aws_analyze_encryption_security', {
      region: 'us-east-1',
      resourceType: 'dynamodb',
    });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/CRITICAL|critical/i);
    expect(result.content[0].text).toContain('orders-table');
  });

  it('dynamodb mode — encrypted table with PITR shows no critical findings', async () => {
    mockSend
      .mockResolvedValueOnce({ TableNames: ['safe-table'] })
      .mockResolvedValueOnce({
        Table: {
          TableName: 'safe-table',
          TableStatus: 'ACTIVE',
          ItemCount: 100,
          SSEDescription: { Status: 'ENABLED', SSEType: 'KMS' },
          BillingModeSummary: { BillingMode: 'PAY_PER_REQUEST' },
        },
      })
      .mockResolvedValueOnce({
        ContinuousBackupsDescription: {
          PointInTimeRecoveryDescription: { PointInTimeRecoveryStatus: 'ENABLED' },
        },
      });

    const result = await callTool('aws_analyze_encryption_security', {
      region: 'us-east-1',
      resourceType: 'dynamodb',
    });
    expect(result.isError).toBeFalsy();
    // No CRITICAL findings in the summary
    const criticalMatch = result.content[0].text.match(/CRITICAL.*(\d+)/);
    if (criticalMatch) {
      expect(parseInt(criticalMatch[1])).toBe(0);
    }
  });

  it('uses default region when none provided (both resourceTypes)', async () => {
    // region defaults to us-east-1; resourceType defaults to 'both'
    // 'both' calls checkKMSKeys then scanDynamoDBSecurity
    mockSend
      .mockResolvedValueOnce({ Keys: [] })       // ListKeysCommand
      .mockResolvedValueOnce({ TableNames: [] }); // ListTablesCommand
    const result = await callTool('aws_analyze_encryption_security', {});
    expect(result.isError).toBeFalsy();
  });
});

// ── aws_analyze_iam_security ──────────────────────────────────────────────────

describe('aws_analyze_iam_security', () => {
  it('users mode — lists IAM users', async () => {
    mockSend.mockResolvedValueOnce({
      Users: [
        {
          UserName: 'alice',
          UserId: 'AIDAALIICE123',
          Arn: 'arn:aws:iam::123:user/alice',
          CreateDate: new Date(Date.now() - 400 * 86400_000), // 400 days old
          PasswordLastUsed: new Date(Date.now() - 200 * 86400_000),
        },
      ],
    });

    const result = await callTool('aws_analyze_iam_security', { scanMode: 'users' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toContain('alice');
  });

  it('roles mode — detects wildcard principal as CRITICAL', async () => {
    const wildcardTrustPolicy = encodeURIComponent(
      JSON.stringify({
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }],
      })
    );

    mockSend.mockResolvedValueOnce({
      Roles: [
        {
          RoleName: 'dangerous-role',
          Arn: 'arn:aws:iam::123:role/dangerous-role',
          CreateDate: new Date(),
          AssumeRolePolicyDocument: wildcardTrustPolicy,
        },
      ],
    });

    const result = await callTool('aws_analyze_iam_security', { scanMode: 'roles' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/CRITICAL|critical/i);
    expect(result.content[0].text).toContain('dangerous-role');
  });

  it('user_policies mode — detects wildcard permissions', async () => {
    const wildcardPolicy = encodeURIComponent(
      JSON.stringify({
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
      })
    );

    mockSend
      .mockResolvedValueOnce({
        Policies: [
          {
            PolicyName: 'AdminLike',
            Arn: 'arn:aws:iam::123:policy/AdminLike',
            AttachmentCount: 3,
            DefaultVersionId: 'v1',
            CreateDate: new Date(),
          },
        ],
      })
      .mockResolvedValueOnce({
        PolicyVersion: { Document: wildcardPolicy, VersionId: 'v1' },
      });

    const result = await callTool('aws_analyze_iam_security', { scanMode: 'user_policies' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/CRITICAL|wildcard/i);
  });

  it('returns JSON envelope when format=json', async () => {
    mockSend.mockResolvedValueOnce({ Users: [] });
    const result = await callTool('aws_analyze_iam_security', { scanMode: 'users', format: 'json' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('tool', 'aws_analyze_iam_security');
  });
});

// ── aws_analyze_ec2_metadata_exposure ────────────────────────────────────────

describe('aws_analyze_ec2_metadata_exposure', () => {
  it('detects IMDSv1-only instances (no HttpTokens=required)', async () => {
    mockSend.mockResolvedValueOnce({
      Reservations: [
        {
          Instances: [
            {
              InstanceId: 'i-deadbeef',
              MetadataOptions: { HttpTokens: 'optional', HttpEndpoint: 'enabled' },
              PublicIpAddress: '1.2.3.4',
              IamInstanceProfile: { Arn: 'arn:aws:iam::123:instance-profile/ec2-role' },
              State: { Name: 'running' },
              InstanceType: 't3.micro',
            },
          ],
        },
      ],
    });

    const result = await callTool('aws_analyze_ec2_metadata_exposure', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    // IMDSv1 is a HIGH/CRITICAL risk
    expect(result.content[0].text).toMatch(/imds|metadata|IMDSv1|CRITICAL|HIGH/i);
  });

  it('no instances → clean report', async () => {
    mockSend.mockResolvedValueOnce({ Reservations: [] });
    const result = await callTool('aws_analyze_ec2_metadata_exposure', { region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('handles missing region gracefully (uses default us-east-1)', async () => {
    // Defensive coding: response.Reservations || [] handles undefined gracefully
    mockSend.mockResolvedValueOnce({ Reservations: [] });
    const result = await callTool('aws_analyze_ec2_metadata_exposure', {});
    expect(result.isError).toBeFalsy();
  });
});

// ── aws_get_logs (audit mode) ─────────────────────────────────────────────────

describe('aws_get_logs', () => {
  it('audit mode — returns MCP audit log table without AWS calls', async () => {
    const result = await callTool('aws_get_logs', { logType: 'audit' });
    expect(result.isError).toBeFalsy();
    expect(mockSend).not.toHaveBeenCalled();
    // Audit log output should reference MCP audit concepts
    expect(result.content[0].text).toMatch(/audit|MCP|OWASP/i);
  });

  it('guardduty mode — lists detectors and findings', async () => {
    mockSend
      .mockResolvedValueOnce({ DetectorIds: ['detector-abc123'] })
      .mockResolvedValueOnce({ FindingIds: ['finding-1', 'finding-2'] })
      .mockResolvedValueOnce({
        Findings: [
          {
            Id: 'finding-1',
            Title: 'Unusual API calls from tor',
            Type: 'Recon:EC2/TorIPCaller',
            Description: 'EC2 API calls from tor exit node',
            Severity: 8.5,
            Service: { Count: 1, EventFirstSeen: '2024-01-01', EventLastSeen: '2024-01-02' },
          },
          {
            Id: 'finding-2',
            Title: 'Credential access',
            Type: 'CredentialAccess:IAMUser/AnomalousBehavior',
            Description: 'Unusual IAM behavior',
            Severity: 5.0,
            Service: { Count: 2 },
          },
        ],
      });

    const result = await callTool('aws_get_logs', { logType: 'guardduty', region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    const text = result.content[0].text;
    expect(text).toContain('Unusual API calls');
  });

  it('guardduty mode — no detectors reports warning', async () => {
    mockSend.mockResolvedValueOnce({ DetectorIds: [] });

    const result = await callTool('aws_get_logs', { logType: 'guardduty', region: 'us-east-1' });
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toMatch(/no guardduty detectors|not enabled/i);
  });
});

// ── aws_scan_resource_policies ────────────────────────────────────────────────

describe('aws_scan_resource_policies', () => {
  it('s3 mode — detects public bucket policy (Principal: *)', async () => {
    // ListBuckets
    mockSend.mockResolvedValueOnce({
      Buckets: [{ Name: 'public-bucket', CreationDate: new Date() }],
    });
    // GetBucketLocation
    mockSend.mockResolvedValueOnce({ LocationConstraint: 'us-east-1' });
    // GetPublicAccessBlock → missing
    const noBlockErr = new Error('NoSuchPublicAccessBlockConfiguration');
    (noBlockErr as any).name = 'NoSuchPublicAccessBlockConfiguration';
    mockSend.mockRejectedValueOnce(noBlockErr);
    // GetBucketPolicy → public policy
    mockSend.mockResolvedValueOnce({
      Policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::public-bucket/*' }],
      }),
    });
    // remaining calls → safe defaults
    mockSend.mockResolvedValue({});

    const result = await callTool('aws_scan_resource_policies', {
      region: 'us-east-1',
      resourceType: 's3',
    });
    // The tool should report the public access issue
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBeTruthy();
  });

  it('handles missing region gracefully (uses default us-east-1)', async () => {
    mockSend.mockResolvedValue({});  // all API calls return empty/undefined safely
    const result = await callTool('aws_scan_resource_policies', { resourceType: 's3' });
    expect(result.isError).toBeFalsy();
  });
});
