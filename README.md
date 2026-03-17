<div align="center">

# Nimbus - AWS Security Assessment MCP Server

[![Version](https://img.shields.io/badge/version-1.15.0-blue.svg)](https://github.com/h4cd0c/nimbus-mcp)
[![Tools](https://img.shields.io/badge/tools-32-green.svg)](https://github.com/h4cd0c/nimbus-mcp)
[![Tests](https://img.shields.io/badge/tests-296%20passing-brightgreen.svg)](https://jestjs.io/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)
[![AWS SDK](https://img.shields.io/badge/AWS%20SDK-v3-yellow.svg)](https://aws.amazon.com/sdk-for-javascript/)
[![Status](https://img.shields.io/badge/status-production%20ready-brightgreen.svg)](https://github.com/h4cd0c/nimbus-mcp)
[![Tests](https://img.shields.io/badge/tests-Jest-green.svg)](https://jestjs.io/)

**Enterprise-grade AWS security assessment toolkit with Attack Chain Builder, 50+ Privesc Patterns & Multi-Region Scanning**

*Designed for security professionals conducting authorized penetration tests, compliance audits, and executive risk reporting*

[Features](#-key-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Examples](#-example-workflows)

</div>

---

## 📖 Overview

**Nimbus** is a comprehensive AWS security assessment framework built on the Model Context Protocol (MCP). It provides 50 production-ready tools covering enumeration, vulnerability scanning, **attack chain building**, privilege escalation analysis (50+ patterns), persistence detection, EKS/Kubernetes security, **multi-region scanning**, and compliance reporting for AWS cloud environments.

### 🎯 Use Cases

- **🔍 Security Assessments** - Identify misconfigurations and vulnerabilities
- **📊 TRA Meetings** - Generate executive-ready risk assessment reports
- **✅ Compliance Audits** - Map findings to CIS, NIST, PCI-DSS, HIPAA frameworks
- **🛡️ Penetration Testing** - Discover attack paths and privilege escalation vectors
- **📈 Risk Management** - Automated risk scoring and remediation roadmaps
- **🌐 Multi-Region Scanning** - Scan all 30+ AWS regions in parallel
- **🔗 Attack Chain Analysis** - Multi-step attack path discovery ⭐ NEW

### ⚡ Key Highlights

✅ **100% Read-Only** - Safe for production environments  
✅ **41 Security Tools** - Comprehensive AWS service coverage  
✅ **Attack Chain Builder** - Multi-step attack path discovery ⭐ NEW  
✅ **50+ Privesc Patterns** - Rhino Security Labs & Heimdall research ⭐ NEW  
✅ **EKS Attack Surface** - IRSA abuse, node role theft, RBAC escalation ⭐ NEW  
✅ **Multi-Region Scanning** - Scan all 30+ regions in parallel  
✅ **Multi-Format Reports** - PDF, HTML, CSV, Markdown  
✅ **TRA Integration** - Risk scoring, compliance mapping, MITRE ATT&CK  
✅ **Zero Cloud Modifications** - No write/delete operations  
✅ **Enterprise Ready** - Professional reports for executives and auditors

## 🎯 Key Features

<table>
<tr>
<td width="50%">

### 🔍 Enumeration (10 Tools)
- **Identity & Access** - IAM users, roles, policies
- **Compute** - EC2 instances, Lambda functions, EKS clusters
- **Storage** - S3 buckets, RDS databases
- **Network** - VPCs, subnets, Security Groups
- **Attack Surface** - Public-facing resources mapping

</td>
<td width="50%">

### 🛡️ Security Scanning (25 Tools)
- **S3 Security** - 7 comprehensive checks (encryption, ACLs, policies)
- **IAM Analysis** - Wildcard permissions, 50+ privilege escalation patterns ⭐
- **Attack Chain Builder** - Multi-step attack path discovery ⭐ NEW
- **Network Security** - Security Groups, VPC exposure, egress points
- **Data Protection** - DynamoDB, ElastiCache, RDS encryption
- **API Security** - API Gateway, CloudFront configuration
- **Messaging** - SNS/SQS encryption and access policies
- **Identity** - Cognito pools, MFA bypass vectors
- **Secrets** - KMS keys, Secrets Manager, SSM parameters
- **Threat Detection** - GuardDuty findings
- **IMDS Security** - EC2 metadata exposure (SSRF risk)
- **Resource Policies** - S3, SQS, SNS, Lambda policy analysis

</td>
</tr>
<tr>
<td width="50%">

### 🔗 Attack Chain Analysis (5 Tools) ⭐ NEW
- **build_attack_chains** - Multi-step attack path discovery
- **analyze_eks_attack_surface** - EKS IRSA & node role abuse
- **detect_privesc_patterns** - 50+ IAM privilege escalation patterns
- **hunt_eks_secrets** - Kubernetes secret enumeration
- **scan_eks_service_accounts** - Service account security audit

</td>
<td width="50%">

### Advanced Security (7 Tools)
- **CloudWatch Security** - Missing alarms, monitoring gaps
- **IAM Escalation** - PassRole abuse, AssumeRole chains
- **SSM Security** - Documents, parameters, session logging
- **IMDS Exposure** - IMDSv1 SSRF risks, instance profiles
- **Resource Policies** - Overly permissive access patterns
- **Network Exposure** - VPC, Transit Gateway, egress analysis
- **Data Exfiltration** - S3 replication, Lambda egress paths

</td>
</tr>
</table>

### 🎯 50+ Privilege Escalation Patterns

| Category | Patterns | Description |
|----------|----------|-------------|
| **PassRole Abuse** | 7 | Lambda, EC2, Glue, CloudFormation, CodeBuild, SageMaker, ECS |
| **Policy Manipulation** | 6 | AttachPolicy, PutPolicy, CreatePolicyVersion |
| **Credential Access** | 4 | CreateAccessKey, LoginProfile, UpdateAssumeRole |
| **EKS Abuse** | 5 | IRSA, Node role theft, Fargate, Cluster admin |
| **Lambda Abuse** | 3 | UpdateFunctionCode, Layers, Env secrets |
| **SSM Abuse** | 3 | SendCommand, StartSession, GetParameters |
| **S3 Abuse** | 2 | Replication, BucketPolicy |
| **Defense Evasion** | 3 | CloudTrail, GuardDuty disable |

### 📄 Report Formats

| Format | Use Case | Features |
|--------|----------|----------|
| **Markdown** | Quick review, documentation | Human-readable, version control friendly |
| **PDF** | Executive presentations, audits | Professional formatting, color-coded severity, charts |
| **HTML** | Interactive dashboards | Sortable tables, collapsible sections, search |
| **CSV** | Data analysis, Excel import | Structured data export for trending |

## 🚀 Quick Start

### 1️⃣ Installation

**Option 1: Install from npm (Recommended)**

```bash
# Install globally from npm
npm install -g nimbus-mcp
```

**Option 2: Build from source**

```bash
# Clone the repository
git clone https://github.com/h4cd0c/nimbus-mcp.git
cd nimbus-mcp

# Install dependencies
npm install

# Build the TypeScript project
npm run build
```

### 2️⃣ AWS Authentication

Configure AWS credentials using one of these methods:

| Method | Command | Use Case |
|--------|---------|----------|
| **AWS CLI** | `aws configure` | Local development, testing |
| **Environment Variables** | `export AWS_ACCESS_KEY_ID=...` | CI/CD, automation |
| **IAM Instance Profile** | Automatic | EC2 instances |
| **IAM Roles** | Automatic | AWS services (Lambda, ECS) |

**Recommended Permissions:** `SecurityAudit` or `ReadOnlyAccess` managed policies

### 3️⃣ MCP Configuration
For VS Code: Add to .vscode/mcp.json

```json
{
  "servers": {
    "nimbus": {
      "command": "node",
      "args": ["C:\\path\\to\\nimbus-mcp\\dist\\index.js"],
      "type": "stdio"
    }
  }
}
```

**Restart VS Code** after configuration.

### 4️⃣ Basic Usage Examples

```bash
# 🔑 Identify current AWS identity
#aws_whoami

# 🌐 Find public-facing resources (attack surface)
#aws_enumerate_public_resources region: us-east-1

# 🔒 Analyze Security Groups for dangerous rules
#aws_analyze_security_groups region: us-east-1

# 🪣 Deep scan S3 bucket security (7 checks)
#aws_scan_s3_bucket_security bucketName: my-production-bucket

# 📊 Generate executive TRA report (PDF)
#aws_generate_security_report region: us-east-1 format: pdf outputFile: C:\reports\aws-security-2026.pdf
```

### 5️⃣ Output Format Control ⭐ NEW

All 43 security tools now support flexible output formatting via the optional `format` parameter:

**Markdown (Default)** - Human-readable output, perfect for documentation and reports
```bash
#aws_whoami
# Returns: Clean markdown text (backward compatible)
```

**JSON** - Machine-readable structured data with metadata for automation
```bash
#aws_whoami format: json
# Returns: { "tool": "aws_whoami", "format": "json", "timestamp": "...", "data": {...} }
```

**Key Benefits:**
- ✅ **Backward Compatible** - Existing tools work without changes (defaults to markdown)
- ✅ **API Integration** - JSON format enables programmatic consumption
- ✅ **Automation** - Parse structured data for CI/CD pipelines
- ✅ **Metadata** - JSON includes tool name, timestamp, and versioning
- ✅ **Flexible** - Choose format per-tool based on use case

**Supported Tools:** All security scanners, enumerators, and analyzers (43 tools total)

**Example Use Cases:**
```bash
# Export scan results to JSON for automation
#aws_analyze_security_groups region: us-east-1 format: json > results.json

# Human-readable documentation output (default)
#aws_scan_s3_bucket_security bucketName: my-bucket

# Structured data for API integration
#aws_detect_privesc_patterns format: json
```

## 📋 Complete Tool Reference

<details>
<summary><b>🔍 Enumeration Tools (10)</b> - Click to expand</summary>

| Tool | Description | Example |
|------|-------------|---------|
| `aws_whoami` | Identify current AWS identity (user/role, account ID, ARN) | `#aws_whoami` |
| `aws_enumerate_ec2_instances` | List EC2 instances with public IPs and security groups | `region: us-east-1` |
| `aws_enumerate_s3_buckets` | List all S3 buckets in the account | No parameters |
| `aws_enumerate_iam_users` | List IAM users with access key ages and last used dates | No parameters |
| `aws_enumerate_iam_roles` | List IAM roles with trust relationships | No parameters |
| `aws_enumerate_rds_databases` | List RDS instances/clusters with public accessibility | `region: us-east-1` |
| `aws_enumerate_vpcs` | List VPCs with subnets and CIDR blocks | `region: us-east-1` |
| `aws_enumerate_lambda_functions` | List Lambda functions with runtimes and IAM roles | `region: us-east-1` |
| `aws_enumerate_eks_clusters` | List EKS clusters with Kubernetes versions | `region: us-east-1` |
| `aws_enumerate_public_resources` | Map public attack surface (EC2, RDS, S3) | `region: us-east-1` |
| `aws_scan_eks_service_accounts` | Analyze EKS service account security (IRSA, OIDC) | `region, clusterName` |
| `aws_hunt_eks_secrets` | Comprehensive K8s secret hunting guide | `region, clusterName` |

</details>

<details>
<summary><b>🌐 Multi-Region Scanning Tools (2)</b> - Click to expand ⭐ NEW</summary>

| Tool | Description | Example |
|------|-------------|---------|
| `aws_scan_all_regions` | Scan multiple AWS regions for resources in parallel. Supports EC2, Lambda, RDS, EKS, Secrets, GuardDuty, ElastiCache, VPC. | `resourceType: ec2, regions: "us-east-1,eu-west-1"` |
| `aws_list_active_regions` | Quick discovery of which regions have resources deployed. Checks EC2, Lambda, RDS counts per region. | `scanMode: common` or `regions: "us-east-1"` |

**Usage Examples:**
```bash
# Single region scan
scan_all_regions --resourceType ec2 --regions "us-east-1"

# Multiple specific regions
scan_all_regions --resourceType lambda --regions "us-east-1,eu-west-1,ap-southeast-1"

# Preset: Common regions (11 popular regions)
scan_all_regions --resourceType rds --scanMode common

# Preset: All regions (30+ regions)
scan_all_regions --resourceType all --scanMode all --parallelism 10

# Discover active regions first
list_active_regions --scanMode common
```

</details>

<details>
<summary><b>🛡️ Security Scanning Tools (13)</b> - Click to expand</summary>

| Tool | Security Checks | Severity Findings |
|------|----------------|-------------------|
| `aws_scan_s3_bucket_security` | Public access, encryption, ACLs, versioning, logging | 🔴 Critical: Public + unencrypted |
| `aws_analyze_security_groups` | 0.0.0.0/0 rules, open ports (SSH, RDP, DB) | 🔴 Critical: Internet-exposed mgmt ports |
| `check_iam_policies` | Wildcard permissions (`*:*`), overly permissive | 🔴 Critical: Admin access wildcards |
| `check_kms_keys` | Key rotation, key policy analysis | 🟡 Medium: Rotation disabled |
| `aws_scan_secrets_manager` | Rotation enabled, encryption, last rotated date | 🟠 High: No rotation in 90+ days |
| `aws_scan_dynamodb_security` | Encryption at rest, PITR, backup retention | 🔴 Critical: No encryption |
| `aws_scan_api_gateway_security` | Logging, throttling, authorization, SSL certificates | 🟠 High: No logging enabled |
| `aws_scan_cloudfront_security` | TLS versions, HTTPS enforcement, WAF, OAI | 🔴 Critical: TLSv1.0 enabled |
| `aws_scan_elasticache_security` | Encryption in-transit/at-rest, auth tokens | 🔴 Critical: No encryption |
| `aws_get_guardduty_findings` | Active threats, malicious IPs, compromised instances | 🔴 Critical: Active threats |
| `aws_scan_sns_security` | Topic encryption (KMS), access policies, HTTP subscriptions | 🔴 Critical: No encryption |
| `aws_scan_sqs_security` | Queue encryption, dead letter queues, access policies | 🔴 Critical: Public queue access |
| `aws_scan_cognito_security` | Unauthenticated access, MFA, password policies | 🔴 Critical: Unauth access enabled |
| `aws_analyze_rds_security` | Public accessibility, encryption, backups, deletion protection, IAM auth (instances/clusters/snapshots) | 🔴 Critical: Public + unencrypted |

</details>

<details>
<summary><b>🎯 Attack Analysis Tools (2)</b> - Click to expand</summary>

| Tool | Analysis | Output |
|------|----------|--------|
| `aws_analyze_attack_paths` | IAM privilege escalation, public → internal vectors | Exploitation scenarios with step-by-step chains |
| `aws_simulate_permissions` | Run `SimulatePrincipalPolicy` against 24 high-value actions; custom action list supported | Allowed/denied breakdown with severity labels for dangerous grants |
| `aws_generate_security_report` | Aggregate all findings, risk scoring, remediation | PDF/HTML/CSV/Markdown reports |

</details>

<details>
<summary><b>📊 TRA (Threat & Risk Assessment) Tool (1) ⭐ NEW</b> - Click to expand</summary>

| Feature | Description | Output |
|---------|-------------|--------|
| **Risk Scoring** | 0-10 automated scale with severity weighting | Risk level: CRITICAL/HIGH/MEDIUM/LOW |
| **Compliance Mapping** | CIS AWS Foundations, NIST 800-53, PCI-DSS, HIPAA | Pass/Fail/Partial for each control |
| **MITRE ATT&CK** | Cloud Matrix tactic and technique mapping | Attack phase classification |
| **Remediation Roadmap** | 4-phase timeline (0-7 days → 3-6 months) | Prioritized action plan |
| **Executive Summary** | One-page risk overview with top 10 critical findings | Board-ready PDF/HTML report |

📚 **[Complete TRA Documentation](TRA_TOOL.md)** - 471 lines with examples and use cases

</details>

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     MCP Client (VS Code)                     │
│                  Claude Dev / Cline Extension                │
└──────────────────────┬──────────────────────────────────────┘
                       │ MCP Protocol
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Nimbus MCP Server (Node.js)                │
│  ┌───────────┬────────────┬──────────────┬────────────┐    │
│  │Enumeration│  Scanning  │Attack Analysis│    TRA     │    │
│  │ (10 tools)│ (13 tools) │  (2 tools)   │  (1 tool)  │    │
│  └───────────┴────────────┴──────────────┴────────────┘    │
└──────────────────────┬──────────────────────────────────────┘
                       │ AWS SDK v3 (21 clients)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                        AWS Cloud                            │
│  ┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐  │
│  │ IAM │ EC2 │ S3  │ RDS │Lambda│EKS │SNS │SQS │Cognito│  │
│  │     │     │     │     │     │    │    │    │       │  │
│  └─────┴─────┴─────┴─────┴─────┴────┴────┴────┴───────┘  │
│  ✅ READ-ONLY Operations | ❌ NO Write/Delete/Modify       │
└─────────────────────────────────────────────────────────────┘
```

### 🔒 Security Model

| Operation Type | Supported | SDK Commands Used |
|----------------|-----------|-------------------|
| **Read** | ✅ Yes | `Get*`, `List*`, `Describe*` |
| **Write** | ❌ No | Not imported in codebase |
| **Delete** | ❌ No | Not imported in codebase |
| **Modify** | ❌ No | Not imported in codebase |

**Verification:** Even with admin credentials (`*:*` permissions), the tool **cannot** modify AWS resources. All SDK commands are read-only by design.

### 🛡️ Input Validation & Auto-Completion ⭐ NEW

**Enhanced Security (OWASP MCP-05 Compliance):**
- **Pattern-Based Validation** - Regex validation for all AWS resource identifiers (ARNs, instance IDs, bucket names, etc.)
- **Whitelist Validation** - Region names and resource types validated against AWS service catalogs
- **Sanitization** - Automatic removal of control characters and length enforcement
- **Clear Error Messages** - Helpful validation errors guide users to correct input formats

**Improved User Experience:**
- **Auto-Completion Support** - Intelligent suggestions for regions, resource types, formats, and scan modes
- **Prefix Filtering** - Type-ahead suggestions as you enter values
- **Context-Aware** - Suggests relevant values based on the current tool and argument

Supported completions:
- `region`/`regions` - All 30 AWS regions + "all", "common"
- `resourceType` - EC2, Lambda, RDS, EKS, Secrets, GuardDuty, ElastiCache, VPC
- `format` - markdown, json, html, pdf, csv
- `scanMode` - common, all
- `severity` - LOW, MEDIUM, HIGH, CRITICAL
- `framework` - nist, iso27001, pci-dss, hipaa, soc2, cis

## 🔍 Security Findings Reference

<table>
<tr>
<th>Severity</th>
<th>Finding Category</th>
<th>Example Issues</th>
<th>Business Impact</th>
</tr>

<tr>
<td rowspan="4">🔴<br><b>CRITICAL</b></td>
<td><b>Public Exposure</b></td>
<td>• EC2 with 0.0.0.0/0 on SSH/RDP<br>• Public RDS databases<br>• S3 public + unencrypted</td>
<td>Direct Internet access → data breach</td>
</tr>

<tr>
<td><b>Data Protection</b></td>
<td>• DynamoDB without encryption<br>• ElastiCache no encryption<br>• SNS/SQS plaintext messages</td>
<td>Sensitive data exposure at rest/in-transit</td>
</tr>

<tr>
<td><b>Access Control</b></td>
<td>• SNS/SQS public access (Principal: *)<br>• Cognito unauthenticated access<br>• S3 bucket ACL public-read</td>
<td>Anonymous access to AWS resources</td>
</tr>

<tr>
<td><b>TLS/SSL</b></td>
<td>• CloudFront TLSv1.0 enabled<br>• API Gateway weak ciphers</td>
<td>Man-in-the-middle attack vulnerability</td>
</tr>

<tr>
<td rowspan="3">🟠<br><b>HIGH</b></td>
<td><b>IAM Security</b></td>
<td>• Wildcard permissions (*:*)<br>• Access keys 90+ days old<br>• No MFA on privileged users</td>
<td>Privilege escalation, credential compromise</td>
</tr>

<tr>
<td><b>Audit & Logging</b></td>
<td>• API Gateway no logging<br>• CloudTrail disabled<br>• No GuardDuty monitoring</td>
<td>No forensic evidence, undetected breaches</td>
</tr>

<tr>
<td><b>Secrets Management</b></td>
<td>• Secrets not rotated 90+ days<br>• Hardcoded creds in Lambda env<br>• KMS keys unrotated</td>
<td>Long-lived credentials increase attack window</td>
</tr>

<tr>
<td rowspan="2">🟡<br><b>MEDIUM</b></td>
<td><b>Resilience</b></td>
<td>• RDS backup retention < 7 days<br>• DynamoDB no PITR<br>• SQS no dead letter queue</td>
<td>Data loss risk, poor disaster recovery</td>
</tr>

<tr>
<td><b>Denial of Service</b></td>
<td>• API Gateway no throttling<br>• No WAF on CloudFront<br>• Lambda no concurrency limits</td>
<td>Service disruption, cost spike attacks</td>
</tr>

</table>

### 📊 Finding Statistics (Typical Enterprise Account)

```
Total Findings: ~80-150
├── 🔴 CRITICAL: 12-25 (15-20%)
├── 🟠 HIGH: 28-45 (35-40%)
├── 🟡 MEDIUM: 30-50 (40-45%)
└── 🟢 LOW: 10-30 (10-15%)

Risk Score: 6.5-7.8 / 10 (HIGH)
Compliance: 60-75% (Typical first scan)
```

## 📚 Documentation

| Document | Description | Lines | Link |
|----------|-------------|-------|------|
| **README.md** | Project overview, quick start, tool reference | 350+ | You're here |
| **USAGE.md** | Detailed workflows, examples, best practices | 400+ | [View](USAGE.md) |
| **TRA_TOOL.md** | Complete TRA guide with compliance frameworks | 471 | [View](TRA_TOOL.md) |
| **COMPLETE.md** | Phase completion summary, achievements | 200+ | [View](COMPLETE.md) |
| **Built-in Help** | Interactive command reference | - | `#aws_help` |

## 🛡️ Security & Compliance

### Required AWS Permissions

**Recommended Managed Policies:**
- ✅ `SecurityAudit` - AWS managed policy for security auditing
- ✅ `ReadOnlyAccess` - Comprehensive read-only access

**Granular Permissions (Minimum Required):**

<details>
<summary>Click to expand IAM policy JSON</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucket*",
        "s3:GetPublicAccessBlock",
        "iam:List*",
        "iam:Get*",
        "rds:Describe*",
        "lambda:List*",
        "lambda:Get*",
        "eks:List*",
        "eks:Describe*",
        "kms:List*",
        "kms:Describe*",
        "secretsmanager:List*",
        "secretsmanager:Describe*",
        "dynamodb:List*",
        "dynamodb:Describe*",
        "apigateway:GET",
        "cloudfront:List*",
        "cloudfront:Get*",
        "elasticache:Describe*",
        "guardduty:List*",
        "guardduty:Get*",
        "sns:List*",
        "sns:Get*",
        "sqs:List*",
        "sqs:Get*",
        "cognito-identity:List*",
        "cognito-identity:Describe*",
        "cognito-idp:List*",
        "cognito-idp:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
```

</details>

### Best Practices

| Practice | Recommendation | Rationale |
|----------|---------------|-----------|
| **Authorization** | Obtain written permission from AWS account owner | Legal compliance, audit trail |
| **Environment** | Test in non-production first | Avoid business disruption |
| **Credentials** | Use temporary credentials (STS AssumeRole) | Minimize credential exposure |
| **Logging** | Enable CloudTrail in target account | Audit all API calls |
| **Documentation** | Record all findings and commands executed | Evidence for remediation |
| **Scope** | Define testing scope (regions, services) | Focused assessment |

### Compliance Frameworks

This tool helps assess compliance with:

- ✅ **CIS AWS Foundations Benchmark** - Security baseline controls
- ✅ **NIST 800-53** - Federal security controls (AC, AU, CM, SC families)
- ✅ **PCI-DSS 3.2.1** - Payment card industry requirements
- ✅ **HIPAA** - Healthcare data protection (encryption, access control)
- ✅ **GDPR** - Data privacy and protection (encryption, audit logging)

## 🎓 Example Workflows

### Workflow 1: 🚀 Quick Security Scan (5 minutes)

**Use Case:** Pre-TRA meeting, rapid assessment

```bash
# Step 1: Verify access
#aws_whoami

# Step 2: Map attack surface
#aws_enumerate_public_resources region: us-east-1

# Step 3: Check network security
#aws_analyze_security_groups region: us-east-1

# Step 4: Generate executive report
#aws_generate_security_report region: us-east-1 format: pdf outputFile: C:\reports\quick-scan.pdf
```

**Expected Output:** 10-20 findings, risk score, top 5 priorities

---

### Workflow 2: 🔐 IAM Security Audit (15 minutes)

**Use Case:** Access control review, privilege escalation testing

```bash
# Step 1: Enumerate all users
#aws_enumerate_iam_users

# Step 2: Enumerate all roles
#aws_enumerate_iam_roles

# Step 3: Check for wildcard permissions
#aws_check_iam_policies

# Step 4: Identify attack paths
#aws_analyze_attack_paths region: us-east-1
```

**Expected Output:** Wildcard policies, old access keys, privilege escalation chains

---

### Workflow 3: 🗄️ Data Security Assessment (20 minutes)

**Use Case:** Compliance audit (encryption, access control)

```bash
# Step 1: List all S3 buckets
#aws_enumerate_s3_buckets

# Step 2: Deep scan critical buckets
#aws_scan_s3_bucket_security bucketName: production-data

# Step 3: Check RDS encryption
#aws_enumerate_rds_databases region: us-east-1

# Step 4: Check DynamoDB security
#aws_scan_dynamodb_security region: us-east-1

# Step 5: Verify secrets rotation
#aws_scan_secrets_manager region: us-east-1
```

**Expected Output:** Unencrypted buckets, public databases, unrotated secrets

---

### Workflow 4: 📊 Complete TRA Report (30 minutes)

**Use Case:** Board meeting, compliance audit, executive briefing

```bash
# Single command for comprehensive assessment
#aws_generate_security_report region: us-east-1 format: pdf outputFile: C:\reports\TRA-Report-2026-Q4.pdf fullScan: true includeCompliance: true includeRemediation: true
```

**Report Includes:**
- ✅ Risk score (0-10 scale) with trend analysis
- ✅ Compliance mapping (CIS, NIST, PCI, HIPAA)
- ✅ MITRE ATT&CK tactics and techniques
- ✅ Remediation roadmap (4 phases: 0-7 days → 3-6 months)
- ✅ Executive summary (one-page overview)
- ✅ Detailed findings by service (50-100 pages)

📚 **[See TRA_TOOL.md for complete guide](TRA_TOOL.md)**

## 🤝 Contributing

We welcome contributions! Here's how to get started:

### Priority Areas for Enhancement

| Category | Enhancement Ideas | Difficulty |
|----------|------------------|------------|
| **New Services** | AWS Config, Systems Manager, WAF, Load Balancers | Medium |
| **Analysis** | CloudTrail log analysis, cost optimization | High |
| **Compliance** | SOC 2, ISO 27001 mapping | Medium |
| **Automation** | Multi-region scanning, scheduled scans | Medium |
| **Remediation** | Auto-generate Terraform/CloudFormation fixes | High |
| **Integrations** | Security Hub, Jira, Slack notifications | Medium |

### Development Workflow

```bash
# 1. Fork and clone
git clone https://github.com/yourusername/nimbus-mcp.git
cd nimbus-mcp

# 2. Create feature branch
git checkout -b feature/new-service-scanner

# 3. Install and build
npm install
npm run build

# 4. Test your changes
npm test  # (add tests for new features)

# 5. Submit pull request
git push origin feature/new-service-scanner
```

### Code Standards

- ✅ TypeScript strict mode
- ✅ Error handling for AWS SDK calls
- ✅ Severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ Documentation in README.md and tool descriptions
- ✅ Test coverage for new tools

## ⚠️ Legal Disclaimer

<div align="center">

**⚠️ AUTHORIZED USE ONLY ⚠️**

This tool is designed for **authorized security testing and compliance auditing only**.

</div>

### User Responsibilities

| Requirement | Description |
|-------------|-------------|
| **Authorization** | Obtain written permission from AWS account owner before testing |
| **Scope** | Only test resources explicitly authorized in writing |
| **Compliance** | Follow AWS Acceptable Use Policy and Customer Agreement |
| **Laws** | Comply with local, state, federal, and international laws |
| **Liability** | Users assume all liability for unauthorized or improper use |

### AWS Acceptable Use Policy

Testing activities must not:
- ❌ Disrupt AWS services or other customers
- ❌ Generate excessive API calls (rate limiting)
- ❌ Access data you don't own
- ❌ Violate privacy or data protection laws

## 📄 License

**MIT License** - See [LICENSE](LICENSE) file for details

Copyright (c) 2026 h4cd0c

---

## 🔗 Resources & References

### AWS Documentation
- 📘 [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- 📘 [IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- 📘 [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- 📘 [AWS Penetration Testing](https://aws.amazon.com/security/penetration-testing/)

### Compliance Frameworks
- 📋 [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- 📋 [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- 📋 [PCI-DSS Cloud Guidelines](https://www.pcisecuritystandards.org/)

### Security Tools & Platforms
- 🛠️ [Model Context Protocol](https://modelcontextprotocol.io/)
- 🛠️ [AWS SDK for JavaScript v3](https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/)
- 🛠️ [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)

---

<div align="center">

## 🌟 Support This Project

If this tool helps your security assessments, please:

⭐ **Star this repository** on GitHub  
🐛 **Report issues** or suggest features  
🤝 **Contribute** code or documentation  
📢 **Share** with your security team

**Built with:** TypeScript • AWS SDK v3 • MCP SDK v1.0.4

**Author:** [h4cd0c](https://github.com/h4cd0c)  
**Repository:** [nimbus-mcp](https://github.com/h4cd0c/nimbus-mcp)

---

Made with ❤️ for the security community

</div>



