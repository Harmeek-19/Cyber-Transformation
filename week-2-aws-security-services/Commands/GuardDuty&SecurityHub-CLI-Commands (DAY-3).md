# Day 3: Complete CLI Commands Reference - GuardDuty + Security Hub Integration

## 🎯 Overview

This document contains all CLI commands executed during Day 3 implementation of GuardDuty threat detection and Enhanced Security Hub integration, including discoveries about advanced GuardDuty features and automatic Security Hub rule creation.

**Key Discovery:** GuardDuty includes advanced protection features (malware scanning, EKS monitoring, RDS events) and Security Hub automatically creates additional Config rules for comprehensive security coverage.

## 📋 Command Categories

### Phase 1: GuardDuty Advanced Setup and Configuration
### Phase 2: Sample Findings Generation and Real Threat Detection
### Phase 3: Enhanced Security Hub Integration with Auto-Rules
### Phase 4: Cross-Service Verification and Advanced Features
### Phase 5: PowerShell Command History and Troubleshooting

---

## 🔧 Phase 1: GuardDuty Advanced Setup and Configuration

### 1.1 Environment Setup

```powershell
# Set MFA-enabled AWS profile
$env:AWS_PROFILE = "admin-mfa"

# Verify identity and MFA access
aws sts get-caller-identity
```

**Expected Output:**
```json
{
    "UserId": "AROA2VQANE7STGEAS3VBI:botocore-session-1755241188",
    "Account": "733366527973",
    "Arn": "arn:aws:sts::733366527973:assumed-role/AdminRole-MFA/botocore-session-1755241188"
}
```

### 1.2 GuardDuty Detector Creation with Advanced Features

**Security Reasoning:** Creates ML engine with comprehensive threat detection across compute, containers, databases, and serverless workloads.

```powershell
# Create GuardDuty detector with rapid finding generation
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES
```

**Result:**
```json
{
    "DetectorId": "52cc564564808e95c18f07ab23b3dd90"
}
```

### 1.3 Comprehensive Detector Configuration Analysis

```powershell
# Get detailed detector configuration with all features
aws guardduty get-detector --detector-id 52cc564564808e95c18f07ab23b3dd90
```

**Complete Feature Set Discovered:**
```json
{
    "CreatedAt": "2025-08-15T07:03:53.660Z",
    "FindingPublishingFrequency": "FIFTEEN_MINUTES",
    "ServiceRole": "arn:aws:iam::733366527973:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
    "Status": "ENABLED",
    "DataSources": {
        "CloudTrail": {"Status": "ENABLED"},
        "DNSLogs": {"Status": "ENABLED"},
        "FlowLogs": {"Status": "ENABLED"},
        "S3Logs": {"Status": "ENABLED"},
        "Kubernetes": {
            "AuditLogs": {"Status": "ENABLED"}
        },
        "MalwareProtection": {
            "ScanEc2InstanceWithFindings": {
                "EbsVolumes": {"Status": "ENABLED"}
            },
            "ServiceRole": "arn:aws:iam::733366527973:role/aws-service-role/malware-protection.guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDutyMalwareProtection"
        }
    },
    "Features": [
        {"Name": "CLOUD_TRAIL", "Status": "ENABLED"},
        {"Name": "DNS_LOGS", "Status": "ENABLED"},
        {"Name": "FLOW_LOGS", "Status": "ENABLED"},
        {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"},
        {"Name": "EKS_AUDIT_LOGS", "Status": "ENABLED"},
        {"Name": "EBS_MALWARE_PROTECTION", "Status": "ENABLED"},
        {"Name": "RDS_LOGIN_EVENTS", "Status": "ENABLED"},
        {"Name": "LAMBDA_NETWORK_LOGS", "Status": "ENABLED"},
        {"Name": "EKS_RUNTIME_MONITORING", "Status": "DISABLED"},
        {"Name": "RUNTIME_MONITORING", "Status": "DISABLED"}
    ]
}
```

**Advanced Features Analysis:**
- ✅ **EKS Audit Logs:** Kubernetes cluster security monitoring
- ✅ **EBS Malware Protection:** Automated malware scanning of EC2 volumes
- ✅ **RDS Login Events:** Database access monitoring
- ✅ **Lambda Network Logs:** Serverless function security analysis
- 🔄 **Runtime Monitoring:** Advanced container/EC2 runtime protection (disabled by default)

### 1.4 Detector Verification

```powershell
# List all detectors
aws guardduty list-detectors
```

**Output:**
```json
{
    "DetectorIds": [
        "52cc564564808e95c18f07ab23b3dd90"
    ]
}
```

---

## 🎯 Phase 2: Sample Findings Generation and Real Threat Detection

### 2.1 Sample Findings Generation Attempts

**Failed Specific Findings Attempt:**
```powershell
# This failed due to invalid finding type names
aws guardduty create-sample-findings --detector-id 52cc564564808e95c18f07ab23b3dd90 --finding-types "Recon:EC2/PortProbeUnprotectedPort" "Trojan:EC2/DNSDataExfiltration" "Backdoor:EC2/XORDDOS" "CryptoCurrency:EC2/BitcoinTool.B" "UnauthorizedAPICall:IAMUser/MaliciousIPCaller.Custom"
```

**Error:** `The request is rejected because of invalid finding type is specified.`

**Successful Comprehensive Approach:**
```powershell
# Generate all available sample findings
aws guardduty create-sample-findings --detector-id 52cc564564808e95c18f07ab23b3dd90
```

**Result:** 363 sample findings generated across all threat categories

### 2.2 Findings Analysis Commands

```powershell
# Count total findings generated
aws guardduty list-findings --detector-id 52cc564564808e95c18f07ab23b3dd90 --query "length(FindingIds)"
```

**Result:** 363 findings confirmed

### 2.3 Real Threat Detection Example

**Actual Security Event Detected:**
During implementation, GuardDuty detected a real security threat:
- **Finding Type:** Suspicious API call pattern
- **Event:** `GetFindingStatisticsV2` called from IP `223.190.81.134`
- **Risk:** Root credentials used from remote IP
- **Analysis:** Not console-generated activity, indicates potential unauthorized access

**Security Investigation Commands:**
```powershell
# Generate real activity for detection testing
aws s3api create-bucket --bucket security-test-findings-$(Get-Random) --region us-east-1
aws s3 ls --recursive
aws iam list-users
aws sts get-caller-identity
```

**Learning:** Real security events trigger actual GuardDuty findings that flow to Security Hub, unlike sample findings which remain in GuardDuty only.

---

## 🔗 Phase 3: Enhanced Security Hub Integration with Auto-Rules

### 3.1 Security Hub Enablement

```powershell
# Enable Enhanced Security Hub with default security standards
aws securityhub enable-security-hub --enable-default-standards
```

**Discovery:** Security Hub automatically creates additional Config rules beyond manually created ones.

### 3.2 Automatic Config Rules Creation

**Manual Rule Created:**
- `s3-bucket-public-read-prohibited`

**Automatically Created by Security Hub:**
```
securityhub-s3-bucket-public-write-prohibited
securityhub-access-keys-rotated
securityhub-acm-certificate-expiration-check
securityhub-iam-user-no-policies-check
securityhub-mfa-enabled-for-root-account
securityhub-alb-http-drop-invalid-header-enabled
securityhub-alb-waf-enabled
```

**Security Reasoning:** Security Hub automatically deploys comprehensive security controls when enabled, providing enterprise-grade compliance monitoring without manual configuration.

### 3.3 Security Standards Verification

```powershell
# Verify enabled security standards
aws securityhub get-enabled-standards
```

**Standards Activated:**
- ✅ CIS AWS Foundations Benchmark v1.2.0
- ✅ AWS Foundational Security Best Practices v1.0.0

### 3.4 Service Integration Configuration

```powershell
# Enable GuardDuty integration
aws securityhub enable-import-findings-for-product --product-arn "arn:aws:securityhub:us-east-1::product/aws/guardduty"

# Enable Config integration  
aws securityhub enable-import-findings-for-product --product-arn "arn:aws:securityhub:us-east-1::product/aws/config"
```

### 3.5 Complete Integration Status

```powershell
# List all enabled product integrations
aws securityhub list-enabled-products-for-import
```

**Result:** 11 product subscriptions enabled including GuardDuty, Config, Inspector, Macie, Access Analyzer, and others.

---

## 🔍 Phase 4: Cross-Service Verification and Advanced Features

### 4.1 Integration Troubleshooting Sequence

**Issue Discovery:** GuardDuty findings not initially appearing in Security Hub

**Troubleshooting Commands:**
```powershell
# Disable GuardDuty integration
aws securityhub disable-import-findings-for-product --product-subscription-arn "arn:aws:securityhub:us-east-1:733366527973:product-subscription/aws/guardduty"

# Wait for cleanup
Start-Sleep -Seconds 60

# Re-enable GuardDuty integration
aws securityhub enable-import-findings-for-product --product-arn "arn:aws:securityhub:us-east-1::product/aws/guardduty"
```

### 4.2 Security Hub Findings Analysis

```powershell
# Check total findings count
aws securityhub get-findings --max-results 1 --query "length(Findings)"

# Analyze finding sources
aws securityhub get-findings --max-results 5 --query "Findings[].{Product:ProductName,Type:Type,Title:Title}" --output table

# Check product distribution
aws securityhub get-findings --max-results 10 --query "Findings[].ProductName" --output text

# Comprehensive findings overview
aws securityhub get-findings --max-results 15 --query "Findings[].[ProductName,Type,SeverityLabel,Title]" --output table
```

### 4.3 GuardDuty-Specific Analysis Attempts

```powershell
# Attempt to filter GuardDuty findings specifically
aws securityhub get-findings --max-results 3 --query "Findings[?ProductName=='GuardDuty'].{Type:Type,Severity:SeverityLabel,Title:Title}" --output table

# File-based filter approach for complex JSON
aws securityhub get-findings --filters file://guardduty-filter.json --max-results 5 --query "Findings[].Title"
```

**File Content (guardduty-filter.json):**
```json
{
  "ProductName": [
    {
      "Value": "GuardDuty",
      "Comparison": "EQUALS"
    }
  ]
}
```

### 4.4 Deep Analysis Commands

```powershell
# Attempt detailed GuardDuty finding analysis
aws guardduty get-findings --detector-id 52cc564564808e95c18f07ab23b3dd90 --finding-ids $(aws guardduty list-findings --detector-id 52cc564564808e95c18f07ab23b3dd90 --max-items 3 --query "FindingIds" --output text) --query "Findings[].{Title:Title,Service:Service.ServiceName,Sample:Service.Archived}" --output table
```

**Note:** This command often returns empty due to PowerShell syntax complexity with large datasets.

---

## 🛠️ Phase 5: PowerShell Command History and Troubleshooting

### 5.1 Complete PowerShell Session History

**From actual PowerShell history:**
```powershell
# Navigation and environment setup
cd .\Downloads\
$env:AWS_PROFILE = "admin-mfa"
aws sts get-caller-identity

# Security Hub filtering attempts (various JSON escaping approaches)
aws securityhub get-findings --filters '{"ProductName":[{"Value":"GuardDuty","Comparison":"EQUALS"}]}' --query...
aws securityhub get-findings --filters "{\"ProductName\":[{\"Value\":\"GuardDuty\",\"Comparison\":\"EQUALS\"}]}...

# Basic finding analysis
aws securityhub get-findings --max-results 1 --query "length(Findings)"
aws securityhub get-findings --max-results 5 --query "Findings[].{Product:ProductName,Type:Type,Title:Title}" --output table
aws securityhub get-findings --max-results 10 --query "Findings[].ProductName" --output text

# File-based filtering
aws securityhub get-findings --filters file://guardduty-filter.json --max-results 5 --query "Findings[].Title"

# GuardDuty verification
aws guardduty list-findings --detector-id 52cc564564808e95c18f07ab23b3dd90 --query "length(FindingIds)"

# Integration management
aws securityhub list-enabled-products-for-import
aws securityhub disable-import-findings-for-product --product-subscription-arn "arn:aws:securityhub:us-east-1:733366527973:product-subscription/aws/guardduty"
Start-Sleep -Seconds 60
aws securityhub enable-import-findings-for-product --product-arn "arn:aws:securityhub:us-east-1::product/aws/guardduty"

# Real activity generation for testing
aws s3api create-bucket --bucket security-test-findings-$(Get-Random) --region us-east-1
aws s3 ls --recursive
aws iam list-users
aws sts get-caller-identity
```

### 5.2 PowerShell-Specific Challenges and Solutions

**Challenge 1: JSON Escaping in PowerShell**
```powershell
# Failed attempts with inline JSON
aws securityhub get-findings --filters '{"ProductName":[{"Value":"GuardDuty","Comparison":"EQUALS"}]}'
aws securityhub get-findings --filters "{\"ProductName\":[{\"Value\":\"GuardDuty\",\"Comparison\":\"EQUALS\"}]}"

# Solution: File-based filters
aws securityhub get-findings --filters file://guardduty-filter.json
```

**Challenge 2: Large Dataset API Limits**
```powershell
# Commands that caused timeouts
aws guardduty get-findings --detector-id 52cc564564808e95c18f07ab23b3dd90 --finding-ids $(aws guardduty list-findings...)

# Solution: Pagination and smaller batches
aws guardduty list-findings --detector-id 52cc564564808e95c18f07ab23b3dd90 --max-items 3
```

---

## 📊 Advanced GuardDuty Features Analysis

### Enterprise Security Coverage

**Complete Protection Matrix:**
```
Data Source          Status    Capability
─────────────────    ──────    ─────────────────────────────
CloudTrail Events    ✅       API call analysis & user behavior
DNS Logs             ✅       Malicious domain detection
VPC Flow Logs        ✅       Network traffic analysis
S3 Data Events       ✅       Data access pattern monitoring
EKS Audit Logs       ✅       Kubernetes security monitoring
EBS Malware Scan     ✅       Automated malware detection
RDS Login Events     ✅       Database access monitoring
Lambda Network       ✅       Serverless security analysis
Runtime Monitoring   🔄       Container/EC2 runtime protection
```

**Security Reasoning for Each Feature:**
- **EKS Audit Logs:** Detects unauthorized Kubernetes operations and container escapes
- **EBS Malware Protection:** Automatically scans EC2 instances when suspicious activity detected
- **RDS Login Events:** Monitors database access patterns for unauthorized access
- **Lambda Network Logs:** Analyzes serverless function network activity for threats

### Cost and Performance Implications

**Active Features (No Additional Cost):**
- CloudTrail, DNS, Flow Logs, S3 Events, EKS Audit Logs, RDS Login Events, Lambda Network Logs

**Premium Features (Additional Cost):**
- EBS Malware Protection (per scan)
- Runtime Monitoring (per agent/hour)

---

## 🔧 Security Hub Automatic Rule Creation Analysis

### Rule Creation Behavior

**When Security Hub is enabled with default standards, it automatically creates Config rules:**

```bash
# Check Config rules after Security Hub enablement
aws configservice describe-config-rules --query 'ConfigRules[].ConfigRuleName' --output table
```

**Automatic Rules Created:**
1. **securityhub-s3-bucket-public-write-prohibited** - Prevents public write access to S3 buckets
2. **securityhub-access-keys-rotated** - Ensures IAM access keys are rotated within 90 days
3. **securityhub-acm-certificate-expiration-check** - Monitors SSL certificate expiration
4. **securityhub-iam-user-no-policies-check** - Prevents direct policy attachment to IAM users
5. **securityhub-mfa-enabled-for-root-account** - Ensures root account has MFA enabled
6. **securityhub-alb-http-drop-invalid-header-enabled** - ALB security header validation
7. **securityhub-alb-waf-enabled** - Ensures ALBs have WAF protection

**Enterprise Value:** Automatic deployment of 100+ security controls without manual configuration effort.

---

## 📋 Complete Command Summary

### Total Commands Executed: 50+
- **Environment Setup:** 5 commands
- **GuardDuty Configuration:** 15 commands
- **Security Hub Integration:** 20 commands
- **Troubleshooting & Analysis:** 15+ commands

### Key Discoveries Through CLI:
1. **GuardDuty Advanced Features:** 9 protection capabilities beyond basic threat detection
2. **Automatic Rule Creation:** Security Hub creates 7+ additional Config rules automatically
3. **Real Threat Detection:** Actual security event detected and analyzed
4. **PowerShell Compatibility:** File-based filters required for complex JSON operations
5. **Integration Complexity:** Multiple verification and reset procedures needed

### Enterprise Implementation Lessons:
1. **Comprehensive Coverage:** GuardDuty provides much more than basic threat detection
2. **Automatic Compliance:** Security Hub deploys extensive controls without manual effort
3. **Real vs. Sample Behavior:** Testing methodology must use actual security events
4. **Multi-Platform Considerations:** PowerShell requires different syntax approaches
5. **Iterative Troubleshooting:** Complex integrations need systematic verification procedures

---

## 🎯 Quick Reference Commands

### Daily Monitoring:
```powershell
# GuardDuty health check
aws guardduty get-detector --detector-id 52cc564564808e95c18f07ab23b3dd90 --query "{Status:Status,Features:Features[?Status=='ENABLED'].Name}"

# Security Hub findings overview
aws securityhub get-findings --max-results 20 --query "Findings[].{Product:ProductName,Severity:SeverityLabel,Title:Title,Updated:UpdatedAt}" --output table

# Integration status verification
aws securityhub list-enabled-products-for-import --query "length(ProductSubscriptions)"
```

### Troubleshooting Commands:
```powershell
# Reset GuardDuty integration
aws securityhub disable-import-findings-for-product --product-subscription-arn "arn:aws:securityhub:us-east-1:733366527973:product-subscription/aws/guardduty"
Start-Sleep -Seconds 60
aws securityhub enable-import-findings-for-product --product-arn "arn:aws:securityhub:us-east-1::product/aws/guardduty"

# Generate test activity
aws sts get-caller-identity
aws s3 ls
aws iam list-users
```

---

**CLI Reference Status: Complete with Real Implementation Data** ✅  
**Advanced Features Documented:** 9 GuardDuty capabilities ✅  
**Automatic Behaviors Captured:** Security Hub rule creation ✅  
**Real Threat Example Included:** Actual security event analysis ✅  
**PowerShell Compatibility:** Complete troubleshooting guide ✅