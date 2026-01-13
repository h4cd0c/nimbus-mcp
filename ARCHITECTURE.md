# AWS Pentest MCP - Architecture Diagram

## 🏗️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              VS CODE / COPILOT                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  User Query: "@aws-pentest enumerate_ec2_instances region: us-east-1"   │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           MCP PROTOCOL LAYER                                     │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐          │
│  │   StdioTransport │───▶│   MCP Server     │◀───│   Tool Registry  │          │
│  │   (JSON-RPC)     │    │   (index.ts)     │    │   (43 Tools)     │          │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘          │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           UTILITY LAYER (utils.ts)                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                       │
│  │    CACHE     │    │ RATE LIMITER │    │    RETRY     │                       │
│  │  (In-Memory) │    │ (Per Service)│    │  (Backoff)   │                       │
│  │  TTL: 2-10m  │    │ 20-100 req/m │    │  3 attempts  │                       │
│  └──────────────┘    └──────────────┘    └──────────────┘                       │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              AWS SDK LAYER                                       │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │   EC2   │ │   IAM   │ │   S3    │ │ Lambda  │ │   RDS   │ │   EKS   │       │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘       │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐       │
│  │Secrets  │ │   KMS   │ │GuardDuty│ │DynamoDB │ │CloudFrnt│ │APIGatwy │       │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘       │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              AWS CLOUD                                           │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                    30+ AWS Regions Available                             │    │
│  │  us-east-1 │ us-west-2 │ eu-west-1 │ ap-southeast-1 │ ... │ il-central-1│    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Request Flow Diagram

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  User    │     │ Copilot  │     │   MCP    │     │  Utils   │     │   AWS    │
│          │     │  Chat    │     │  Server  │     │  Layer   │     │   API    │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │                │
     │  @aws-pentest  │                │                │                │
     │  enumerate_ec2 │                │                │                │
     │───────────────▶│                │                │                │
     │                │                │                │                │
     │                │  JSON-RPC      │                │                │
     │                │  CallTool      │                │                │
     │                │───────────────▶│                │                │
     │                │                │                │                │
     │                │                │  Check Cache   │                │
     │                │                │───────────────▶│                │
     │                │                │                │                │
     │                │                │  Cache MISS    │                │
     │                │                │◀───────────────│                │
     │                │                │                │                │
     │                │                │  Rate Limit OK │                │
     │                │                │───────────────▶│                │
     │                │                │                │                │
     │                │                │                │  DescribeEC2   │
     │                │                │                │───────────────▶│
     │                │                │                │                │
     │                │                │                │   Response     │
     │                │                │                │◀───────────────│
     │                │                │                │                │
     │                │                │  Store Cache   │                │
     │                │                │───────────────▶│                │
     │                │                │                │                │
     │                │  Markdown      │                │                │
     │                │  Response      │                │                │
     │                │◀───────────────│                │                │
     │                │                │                │                │
     │  Formatted     │                │                │                │
     │  Results       │                │                │                │
     │◀───────────────│                │                │                │
     │                │                │                │                │
```

---

## 📦 Cache Flow Diagram

```
                    ┌─────────────────────────────────┐
                    │         INCOMING REQUEST        │
                    │   enumerate_ec2 (us-east-1)     │
                    └───────────────┬─────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────┐
                    │      CHECK CACHE                │
                    │   Key: "ec2:instances:us-east-1"│
                    └───────────────┬─────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
        ┌───────────────────┐           ┌───────────────────┐
        │    CACHE HIT      │           │   CACHE MISS      │
        │   (< 2 min old)   │           │  (expired/empty)  │
        └─────────┬─────────┘           └─────────┬─────────┘
                  │                               │
                  │                               ▼
                  │                   ┌───────────────────┐
                  │                   │   withRetry()     │
                  │                   │   Call AWS API    │
                  │                   └─────────┬─────────┘
                  │                             │
                  │                             ▼
                  │                   ┌───────────────────┐
                  │                   │   STORE IN CACHE  │
                  │                   │   TTL: 120000ms   │
                  │                   └─────────┬─────────┘
                  │                             │
                  ▼                             ▼
        ┌───────────────────────────────────────────────┐
        │              RETURN RESPONSE                   │
        │  📦 Cached indicator if from cache             │
        └───────────────────────────────────────────────┘
```

---

## 🌐 Multi-Region Scanning Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      scan_all_regions (resourceType: ec2)                        │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         PARSE REGIONS PARAMETER                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐              │
│  │ Custom Regions   │  │ "common" Preset  │  │  "all" Preset    │              │
│  │ "us-east-1,eu-*" │  │   (11 regions)   │  │  (30+ regions)   │              │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     PARALLEL EXECUTION (parallelism: 5)                          │
│                                                                                  │
│   Batch 1                    Batch 2                    Batch 3                  │
│  ┌─────────┐                ┌─────────┐                ┌─────────┐              │
│  │us-east-1│                │eu-west-1│                │ap-south-1│              │
│  │us-east-2│                │eu-west-2│                │ap-north-1│              │
│  │us-west-1│                │eu-central│               │ap-south-2│              │
│  │us-west-2│                │eu-north-1│               │    ...   │              │
│  │ca-cent-1│                │sa-east-1 │               │    ...   │              │
│  └────┬────┘                └────┬────┘                └────┬────┘              │
│       │                          │                          │                    │
│       ▼                          ▼                          ▼                    │
│  ┌─────────┐                ┌─────────┐                ┌─────────┐              │
│  │ Results │                │ Results │                │ Results │              │
│  └─────────┘                └─────────┘                └─────────┘              │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          AGGREGATE RESULTS                                       │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │  # Multi-Region EC2 Scan Results                                         │   │
│  │  ## us-east-1: 15 instances (🔴 3 public IPs)                           │   │
│  │  ## eu-west-1: 8 instances (✅ no issues)                               │   │
│  │  ## ap-south-1: 0 instances                                              │   │
│  │  ...                                                                      │   │
│  │  ## Summary: 45 total instances, 3 critical findings                     │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tool Categories

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         AWS PENTEST MCP - 43 TOOLS                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  📋 UTILITY (2)                                                          │    │
│  │  help, whoami                                                            │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  🔍 ENUMERATION (8)                                                      │    │
│  │  enumerate_ec2_instances, enumerate_iam_roles, enumerate_rds_databases,  │    │
│  │  enumerate_eks_clusters, enumerate_public_resources,                     │    │
│  │  enumerate_organizations, enumerate_detection_services,                  │    │
│  │  list_active_regions                                                     │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  🛡️ SECURITY ANALYSIS (14)                                               │    │
│  │  analyze_s3_security, analyze_iam_users, analyze_network_security,       │    │
│  │  analyze_lambda_security, analyze_encryption_security,                   │    │
│  │  analyze_api_distribution_security, analyze_messaging_security,          │    │
│  │  analyze_infrastructure_automation, analyze_cloudwatch_security,         │    │
│  │  analyze_iam_privilege_escalation, analyze_ec2_metadata_exposure,        │    │
│  │  analyze_network_exposure, analyze_iam_trust_chains,                     │    │
│  │  analyze_attack_paths                                                    │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  🎯 ATTACK DETECTION (7)                                                 │    │
│  │  detect_permissive_roles, detect_cross_account_access,                   │    │
│  │  detect_service_role_risks, detect_persistence_mechanisms,               │    │
│  │  detect_mfa_bypass_vectors, detect_data_exfiltration_paths,              │    │
│  │  analyze_cross_account_movement                                          │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  🔎 SCANNING (8)                                                         │    │
│  │  scan_secrets_manager, scan_elasticache_security, scan_ssm_security,     │    │
│  │  scan_resource_policies, scan_privilege_escalation_paths,                │    │
│  │  scan_for_backdoors, scan_eks_service_accounts, scan_all_regions         │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  🔗 TRUST CHAINS (2)                                                     │    │
│  │  analyze_service_role_chain, hunt_eks_secrets                            │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  📊 REPORTING (3)                                                        │    │
│  │  generate_security_report, generate_tra_report, get_guardduty_findings   │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │  📦 CACHE MANAGEMENT (2)                                                 │    │
│  │  cache_stats, cache_clear                                                │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         AWS CREDENTIAL CHAIN                                     │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
            ┌───────────────────────────┼───────────────────────────┐
            │                           │                           │
            ▼                           ▼                           ▼
┌───────────────────┐       ┌───────────────────┐       ┌───────────────────┐
│  1. Environment   │       │  2. Shared Creds  │       │  3. IAM Role      │
│     Variables     │       │  ~/.aws/creds     │       │  (EC2/ECS/Lambda) │
│  AWS_ACCESS_KEY   │       │  [default]        │       │  Instance Profile │
│  AWS_SECRET_KEY   │       │  [profile-name]   │       │                   │
└─────────┬─────────┘       └─────────┬─────────┘       └─────────┬─────────┘
          │                           │                           │
          └───────────────────────────┼───────────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────┐
                    │      AWS SDK AUTO-RESOLVE       │
                    │   (First valid credential wins) │
                    └─────────────────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────┐
                    │      STS GetCallerIdentity      │
                    │      (whoami verification)      │
                    └─────────────────────────────────┘
```

---

## 📁 File Structure

```
aws-pentest/
├── src/
│   ├── index.ts          # Main MCP Server (6000+ lines)
│   │   ├── TOOLS[]       # 43 tool definitions
│   │   ├── Handlers      # Tool request handlers
│   │   └── Functions     # Implementation functions
│   │
│   └── utils.ts          # Utilities (430 lines)
│       ├── Cache         # In-memory cache with TTL
│       ├── RateLimiter   # Per-service rate limiting
│       └── withRetry     # Exponential backoff retry
│
├── dist/                 # Compiled JavaScript
│   ├── index.js
│   └── utils.js
│
├── package.json          # v1.4.0, 43 tools
├── tsconfig.json         # TypeScript config
├── CHANGELOG.md          # Version history
├── README.md             # Documentation
├── USAGE.md              # Usage examples
└── ARCHITECTURE.md       # This file
```

---

## 🚀 Startup Sequence

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              MCP SERVER STARTUP                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

    ┌─────────┐
    │  START  │
    └────┬────┘
         │
         ▼
    ┌─────────────────────────────────────┐
    │  1. Load Environment Variables       │
    │     AWS_REGION || us-east-1          │
    └───────────────┬─────────────────────┘
                    │
                    ▼
    ┌─────────────────────────────────────┐
    │  2. Initialize AWS SDK Clients       │
    │     EC2, S3, IAM, RDS, EKS...       │
    └───────────────┬─────────────────────┘
                    │
                    ▼
    ┌─────────────────────────────────────┐
    │  3. Initialize Utility Layer         │
    │     Cache, RateLimiters, Retry       │
    └───────────────┬─────────────────────┘
                    │
                    ▼
    ┌─────────────────────────────────────┐
    │  4. Create MCP Server Instance       │
    │     name: "aws-pentest-mcp"          │
    │     version: "1.4.0"                 │
    └───────────────┬─────────────────────┘
                    │
                    ▼
    ┌─────────────────────────────────────┐
    │  5. Register Request Handlers        │
    │     ListToolsRequestSchema           │
    │     CallToolRequestSchema            │
    └───────────────┬─────────────────────┘
                    │
                    ▼
    ┌─────────────────────────────────────┐
    │  6. Connect StdioTransport           │
    │     stdin/stdout JSON-RPC            │
    └───────────────┬─────────────────────┘
                    │
                    ▼
    ┌─────────────────────────────────────┐
    │  7. READY - Listening for Requests   │
    │     "AWS Pentest MCP running..."     │
    └─────────────────────────────────────┘
```

---

## 📊 Cache TTL Strategy

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CACHE TTL BY SERVICE                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  Service          │  TTL      │  Reason                                         │
│  ─────────────────┼───────────┼────────────────────────────────────────────────│
│  EC2 Instances    │  2 min    │  Instances can start/stop frequently            │
│  IAM Roles        │  10 min   │  Global service, rarely changes                 │
│  S3 Buckets       │  10 min   │  Bucket configs rarely change (future)          │
│  Lambda Functions │  5 min    │  Deployments happen occasionally (future)       │
│  Security Groups  │  5 min    │  Network rules semi-stable (future)             │
│  Default          │  5 min    │  Fallback for unlisted services                 │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

Currently Cached: EC2, IAM
Future: S3, Lambda, RDS, EKS, Security Groups (when needed)
```

---

*Generated: January 12, 2026*
*AWS Pentest MCP v1.4.0*
