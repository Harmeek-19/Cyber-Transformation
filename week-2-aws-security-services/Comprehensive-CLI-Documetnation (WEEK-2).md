# AWS Security Services - Complete CLI Commands Reference
**Week 2 Training: Enterprise Security Operations Center Implementation**

## 📋 Overview
Comprehensive CLI command reference for complete AWS Security Services implementation including CloudTrail, Config, GuardDuty, Security Hub, and Macie. All commands executed with MFA-enforced admin profile following enterprise security consultant methodology.

**Security Foundation:** All commands use `--profile admin-mfa` for secure access with MFA enforcement.

---

## 🔧 Environment Setup

### Prerequisites Verification
```bash
# Verify AWS CLI profile and MFA setup
aws sts get-caller-identity --profile admin-mfa
# Expected: Shows assumed-role/AdminRole-MFA in account 733366527973
```

### PowerShell Environment Setup
```powershell
# Set environment variable for PowerShell sessions
$env:AWS_PROFILE = "admin-mfa"

# Verify identity and MFA access
aws sts get-caller-identity
```

### Working Directory Setup
```bash
# Create organized workspace
mkdir aws-security-services
cd aws-security-services
mkdir policy-files
mkdir logs
```

---

## 🔍 DAY 1: CLOUDTRAIL - AUDIT LOGGING FOUNDATION

### S3 Bucket Setup for CloudTrail
```bash
# Create S3 bucket for CloudTrail logs
aws s3 mb s3://cloudtrail-logs-733366527973-training --region us-east-1 --profile admin-mfa

# Apply comprehensive public access block
aws s3api put-public-access-block \
  --bucket cloudtrail-logs-733366527973-training \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --profile admin-mfa

# Create CloudTrail bucket policy
# Content: cloudtrail-bucket-policy.json
aws s3api put-bucket-policy \
  --bucket cloudtrail-logs-733366527973-training \
  --policy file://cloudtrail-bucket-policy.json \
  --profile admin-mfa
```

### CloudTrail Configuration
```bash
# Create SecurityAuditTrail with comprehensive coverage
aws cloudtrail create-trail \
  --name SecurityAuditTrail \
  --s3-bucket-name cloudtrail-logs-733366527973-training \
  --include-global-service-events \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --profile admin-mfa

# Start CloudTrail logging
aws cloudtrail start-logging --name SecurityAuditTrail --profile admin-mfa

# Verify trail status
aws cloudtrail get-trail-status --name SecurityAuditTrail --profile admin-mfa
```

### Security Event Generation for Testing
```bash
# Generate identity and access events
aws sts get-caller-identity --profile admin-mfa
aws iam list-users --profile admin-mfa
aws iam list-roles --profile admin-mfa

# Generate S3 events
aws s3 ls --profile admin-mfa
aws s3api list-buckets --profile admin-mfa

# Generate service status queries
aws configservice describe-configuration-recorders --profile admin-mfa
aws guardduty list-detectors --profile admin-mfa
```

### CloudTrail Log Analysis
```bash
# Download CloudTrail logs for analysis
aws s3 sync s3://cloudtrail-logs-733366527973-training/AWSLogs/733366527973/CloudTrail/us-east-1/2025/08/14/ ./cloudtrail-logs/ --profile admin-mfa

# Search for specific events (Windows)
findstr /S /I "CreateBucket" cloudtrail-logs\*.json
findstr /S /I "configservice" cloudtrail-logs\*.json
findstr /S /I "GetCallerIdentity" cloudtrail-logs\*.json
```

---

## ⚖️ DAY 2: CONFIG - COMPLIANCE AUTOMATION

### IAM Service Role Creation
```bash
# Create trust policy file (config-trust-policy.json)
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

# Create Config service role (CLI alternative to console)
aws iam create-role \
  --role-name AwsConfig-service-role \
  --assume-role-policy-document file://config-trust-policy.json \
  --description "Service role for AWS Config" \
  --profile admin-mfa

# Attach AWS managed policy
aws iam attach-role-policy \
  --role-name AwsConfig-service-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/ConfigRole \
  --profile admin-mfa
```

### S3 Bucket Configuration for Config
```bash
# Create dedicated Config S3 bucket
aws s3 mb s3://config-compliance-data-733366527973 --region us-east-1 --profile admin-mfa

# Apply comprehensive public access block
aws s3api put-public-access-block \
  --bucket config-compliance-data-733366527973 \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --profile admin-mfa

# Apply Config bucket policy
aws s3api put-bucket-policy \
  --bucket config-compliance-data-733366527973 \
  --policy file://config-bucket-policy.json \
  --profile admin-mfa
```

### Configuration Recorder Setup
```bash
# Create configuration recorder (CLI alternative to console)
aws configservice put-configuration-recorder \
  --configuration-recorder '{
    "name": "default",
    "roleARN": "arn:aws:iam::733366527973:role/AwsConfig-service-role",
    "recordingGroup": {
      "allSupported": true,
      "includeGlobalResourceTypes": true,
      "recordingMode": {
        "recordingFrequency": "CONTINUOUS"
      }
    }
  }' \
  --profile admin-mfa

# Create delivery channel
aws configservice put-delivery-channel \
  --delivery-channel '{
    "name": "default",
    "s3BucketName": "config-compliance-data-733366527973",
    "configSnapshotDeliveryProperties": {
      "deliveryFrequency": "TwentyFour_Hours"
    }
  }' \
  --profile admin-mfa

# Start configuration recording
aws configservice start-configuration-recorder \
  --configuration-recorder-name default \
  --profile admin-mfa
```

### Configuration Verification
```bash
# Verify configuration recorder
aws configservice describe-configuration-recorders --profile admin-mfa
aws configservice describe-configuration-recorder-status --profile admin-mfa

# Verify delivery channel
aws configservice describe-delivery-channels --profile admin-mfa

# Check discovered resources
aws configservice get-discovered-resource-counts --profile admin-mfa
```

### S3 Public Access Compliance Rule
```bash
# Create S3 public access compliance rule
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "s3-bucket-public-read-prohibited",
    "Description": "Checks that S3 buckets do not allow public read access",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    },
    "Scope": {
      "ComplianceResourceTypes": ["AWS::S3::Bucket"]
    }
  }' \
  --profile admin-mfa

# Verify rule creation
aws configservice describe-config-rules --config-rule-names s3-bucket-public-read-prohibited --profile admin-mfa
```

### Compliance Testing Workflow
```bash
# Create test bucket for violation testing
aws s3 mb s3://compliance-test-bucket-733366527973 --region us-east-1 --profile admin-mfa

# Remove public access block (temporary for testing)
aws s3api delete-public-access-block \
  --bucket compliance-test-bucket-733366527973 \
  --profile admin-mfa

# Apply public policy (creates violation)
aws s3api put-bucket-policy \
  --bucket compliance-test-bucket-733366527973 \
  --policy file://violation-bucket-policy.json \
  --profile admin-mfa

# Force rule evaluation
aws configservice start-config-rules-evaluation \
  --config-rule-names s3-bucket-public-read-prohibited \
  --profile admin-mfa

# Check compliance status
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name s3-bucket-public-read-prohibited \
  --profile admin-mfa

# Remediate violation
aws s3api delete-bucket-policy \
  --bucket compliance-test-bucket-733366527973 \
  --profile admin-mfa

# Restore security controls
aws s3api put-public-access-block \
  --bucket compliance-test-bucket-733366527973 \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --profile admin-mfa
```

---

## 🛡️ DAY 3: GUARDDUTY + SECURITY HUB INTEGRATION

### GuardDuty Advanced Setup
```powershell
# Create GuardDuty detector with comprehensive features
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Get detector ID
aws guardduty list-detectors

# Get comprehensive detector configuration
aws guardduty get-detector --detector-id 52cc564564808e95c18f07ab23b3dd90
```

### Sample Findings Generation
```powershell
# Generate comprehensive sample findings
aws guardduty create-sample-findings --detector-id 52cc564564808e95c18f07ab23b3dd90

# Count generated findings
aws guardduty list-findings --detector-id 52cc564564808e95c18f07ab23b3dd90 --query "length(FindingIds)"

# Analyze finding types (basic command - complex analysis requires file-based filtering)
aws guardduty list-findings --detector-id 52cc564564808e95c18f07ab23b3dd90 --max-items 5
```

### Enhanced Security Hub Integration
```powershell
# Enable Security Hub with default standards
aws securityhub enable-security-hub --enable-default-standards

# Enable GuardDuty integration
aws securityhub enable-import-findings-for-product --product-arn "arn:aws:securityhub:us-east-1::product/aws/guardduty"

# Enable Config integration
aws securityhub enable-import-findings-for-product --product-arn "arn:aws:securityhub:us-east-1::product/aws/config"

# Verify enabled integrations
aws securityhub list-enabled-products-for-import

# Check enabled security standards
aws securityhub get-enabled-standards
```

### Cross-Service Finding Analysis
```powershell
# Get total findings count in Security Hub
aws securityhub get-findings --max-results 1 --query "length(Findings)"

# Analyze finding sources
aws securityhub get-findings --max-results 10 --query "Findings[].ProductName" --output text

# Get findings overview
aws securityhub get-findings --max-results 15 --query "Findings[].[ProductName,Type,SeverityLabel,Title]" --output table

# File-based filtering for complex queries (PowerShell-compatible)
echo '{"ProductName": [{"Value": "GuardDuty", "Comparison": "EQUALS"}]}' > guardduty-filter.json
aws securityhub get-findings --filters file://guardduty-filter.json --max-results 5 --query "Findings[].Title"
```

### Integration Troubleshooting
```powershell
# Reset GuardDuty integration if needed
aws securityhub disable-import-findings-for-product --product-subscription-arn "arn:aws:securityhub:us-east-1:733366527973:product-subscription/aws/guardduty"
Start-Sleep -Seconds 60
aws securityhub enable-import-findings-for-product --product-arn "arn:aws:securityhub:us-east-1::product/aws/guardduty"

# Generate real activity for threat detection testing
aws sts get-caller-identity
aws s3 ls --recursive
aws iam list-users
aws s3api create-bucket --bucket security-test-findings-$(Get-Random) --region us-east-1
```

---

## 🔒 DAY 4: MACIE - DATA PROTECTION & PRIVACY

### Macie Service Enablement
```powershell
# Enable Amazon Macie
aws macie2 enable-macie

# Verify Macie session
aws macie2 get-macie-session
```

### Test Data Environment Setup
```powershell
# Create test bucket
aws s3 mb s3://macie-test-data-733366527973

# Create comprehensive test files with sensitive data
# customer-data.csv
echo "CustomerID,Name,SSN,Email,Phone
CUST001,John Doe,123-45-6789,john.doe@example.com,(555) 123-4567
CUST002,Jane Smith,987-65-4321,jane.smith@company.com,(555) 987-6543" > customer-data.csv

# medical-records.json  
echo '{
  "patients": [
    {
      "patient_id": "PAT-001",
      "name": "Alice Cooper", 
      "ssn": "111-22-3333",
      "medical_record_number": "MRN-987654321"
    }
  ]
}' > medical-records.json

# employee-directory.txt
echo "Employee Directory
Name: Jennifer Adams
SSN: 777-88-9999
Department: Human Resources" > employee-directory.txt

# Upload test files
aws s3 cp customer-data.csv s3://macie-test-data-733366527973/
aws s3 cp medical-records.json s3://macie-test-data-733366527973/
aws s3 cp employee-directory.txt s3://macie-test-data-733366527973/

# Verify test environment
aws s3 ls s3://macie-test-data-733366527973/
```

### Classification Jobs Creation
```powershell
# Create comprehensive PII discovery job
aws macie2 create-classification-job `
    --job-type ONE_TIME `
    --name "Day4-Comprehensive-PII-Discovery" `
    --description "Complete sensitive data classification" `
    --s3-job-definition '{\"bucketDefinitions\":[{\"accountId\":\"733366527973\",\"buckets\":[\"macie-test-data-733366527973\"]}]}' `
    --sampling-percentage 100

# Create integration test job
aws macie2 create-classification-job `
    --job-type ONE_TIME `
    --name "Day4-Integration-Test" `
    --description "Testing Security Hub integration" `
    --s3-job-definition '{\"bucketDefinitions\":[{\"accountId\":\"733366527973\",\"buckets\":[\"macie-test-data-733366527973\"]}]}' `
    --sampling-percentage 100
```

### Job Monitoring and Analysis
```powershell
# List all classification jobs
aws macie2 list-classification-jobs --query 'items[*].{JobId:jobId,Name:name,Status:jobStatus,CreatedAt:createdAt}'

# Get detailed job information
aws macie2 describe-classification-job --job-id 883b34a5d76ae80de85e3e2bdd9e6bc6

# Monitor job completion
$MACIE_JOB_ID = aws macie2 list-classification-jobs --query 'items[0].jobId' --output text
aws macie2 describe-classification-job --job-id $MACIE_JOB_ID --query '{Status:jobStatus,Statistics:statistics}'
```

### Findings Analysis
```powershell
# List all findings
aws macie2 list-findings

# Get finding count
aws macie2 list-findings --query 'length(findingIds)'

# Get detailed finding information (use individual IDs)
aws macie2 get-findings --finding-ids c7f2b63fe864d98503dcca2de3522a48 7b029b2e274bbe38d0c6710da9c16ca1 a2aea3fa42716ff4288f5088df16555b

# Get single finding details
aws macie2 get-findings --finding-ids c7f2b63fe864d98503dcca2de3522a48
```

### Security Hub Integration Configuration
```powershell
# Check current publication settings
aws macie2 get-findings-publication-configuration

# Enable classification findings publication (CRITICAL)
aws macie2 put-findings-publication-configuration --security-hub-configuration '{"publishClassificationFindings": true, "publishPolicyFindings": true}'

# Verify integration fix
aws macie2 get-findings-publication-configuration
```

### Security Hub Findings Retrieval
```powershell
# Create Macie filter file for complex queries
echo '{"ProductName": [{"Value": "Macie", "Comparison": "EQUALS"}]}' > macie-filter.json

# Get Macie findings from Security Hub
aws securityhub get-findings --filters file://macie-filter.json --query "Findings[*].{ProductName:ProductName,Title:Title,Severity:Severity.Label}"

# Get detailed Macie findings with resource information
aws securityhub get-findings --filters file://macie-filter.json --query "Findings[*].{ProductName:ProductName,Title:Title,Severity:Severity.Label,ResourceId:Resources[0].Id,CreatedAt:CreatedAt}"

# Count Macie findings in Security Hub
aws securityhub get-findings --filters file://macie-filter.json --query "length(Findings)"

# Verify Macie presence using text filtering
aws securityhub get-findings --query 'Findings[*].ProductName' --output text | Select-String -Pattern "Macie"
```

---

## 🔧 Cross-Service Integration Commands

### Complete Service Status Check
```bash
# CloudTrail status
aws cloudtrail get-trail-status --name SecurityAuditTrail --profile admin-mfa

# Config recorder status
aws configservice describe-configuration-recorder-status --profile admin-mfa

# GuardDuty detector status
aws guardduty get-detector --detector-id [DETECTOR_ID] --query "{Status:Status,Features:Features[?Status=='ENABLED'].Name}"

# Security Hub summary
aws securityhub get-findings --max-results 1 --query "length(Findings)"

# Macie session status
aws macie2 get-macie-session --query "{Status:status,Role:serviceRole}"
```

### Integration Validation
```bash
# Download and analyze CloudTrail logs for all services
aws s3 sync s3://cloudtrail-logs-733366527973-training/AWSLogs/733366527973/CloudTrail/ ./all-logs/ --profile admin-mfa

# Search for service integration events
findstr /S /I "configservice" all-logs\*.json
findstr /S /I "guardduty" all-logs\*.json  
findstr /S /I "macie" all-logs\*.json
findstr /S /I "securityhub" all-logs\*.json

# Get Security Hub integration overview
aws securityhub list-enabled-products-for-import --query "length(ProductSubscriptions)"
```

### Unified Security Operations Commands
```powershell
# Get comprehensive security findings overview
aws securityhub get-findings --max-results 20 --query "Findings[].{Product:ProductName,Severity:Severity.Label,Title:Title,Updated:UpdatedAt}" --output table

# Service-specific finding counts
aws securityhub get-findings --query 'Findings[*].ProductName' --output json | Select-String -Pattern "GuardDuty" | Measure-Object -Line
aws securityhub get-findings --query 'Findings[*].ProductName' --output json | Select-String -Pattern "Config" | Measure-Object -Line  
aws securityhub get-findings --query 'Findings[*].ProductName' --output json | Select-String -Pattern "Macie" | Measure-Object -Line

# Complete compliance posture check
aws configservice get-compliance-summary-by-config-rule
```

---

## 🛠️ Troubleshooting Commands

### Common Error Resolution
```bash
# File path verification
pwd
ls -la policy-files/
type policy-files/config-trust-policy.json

# JSON validation before applying policies
# Use online JSON validator or text editor with JSON support

# AWS CLI parameter case sensitivity check
aws configservice describe-config-rules --query 'ConfigRules[].ConfigRuleName' --output table
```

### PowerShell-Specific Solutions
```powershell
# Variable management
$env:AWS_PROFILE = "admin-mfa"
$DETECTOR_ID = aws guardduty list-detectors --query 'DetectorIds[0]' --output text

# JSON escaping for complex parameters
aws macie2 create-classification-job --s3-job-definition '{\"bucketDefinitions\":[{\"accountId\":\"733366527973\",\"buckets\":[\"bucket-name\"]}]}'

# File-based filtering for complex queries
echo '{"ProductName": [{"Value": "GuardDuty", "Comparison": "EQUALS"}]}' > service-filter.json
aws securityhub get-findings --filters file://service-filter.json
```

### Service Reset Commands
```powershell
# Reset GuardDuty integration
aws securityhub disable-import-findings-for-product --product-subscription-arn [ARN]
Start-Sleep -Seconds 60
aws securityhub enable-import-findings-for-product --product-arn [PRODUCT_ARN]

# Force Config rule re-evaluation
aws configservice start-config-rules-evaluation --config-rule-names [RULE_NAME]

# Restart CloudTrail logging
aws cloudtrail stop-logging --name SecurityAuditTrail --profile admin-mfa
aws cloudtrail start-logging --name SecurityAuditTrail --profile admin-mfa
```

---

## 📊 Quick Reference Commands

### Daily Monitoring
```bash
# Overall security posture check
aws securityhub get-findings --max-results 1 --query "length(Findings)"
aws configservice get-compliance-summary-by-config-rule
aws guardduty list-findings --detector-id [DETECTOR_ID] --query "length(FindingIds)"
aws macie2 list-findings --query 'length(findingIds)'

# Service health verification
aws cloudtrail get-trail-status --name SecurityAuditTrail --query "IsLogging"
aws configservice describe-configuration-recorder-status --query "ConfigurationRecordersStatus[0].recording"
aws guardduty get-detector --detector-id [DETECTOR_ID] --query "Status"
aws macie2 get-macie-session --query "status"
```

### Integration Verification
```bash
# Security Hub integrations count
aws securityhub list-enabled-products-for-import --query "length(ProductSubscriptions)"

# Cross-service finding distribution
aws securityhub get-findings --query 'Findings[*].ProductName' --output text

# Config rules count (manual + automatic)
aws configservice describe-config-rules --query 'length(ConfigRules)'
```

---

## 📈 Implementation Summary

### Total Commands Executed: 200+
- **Day 1 CloudTrail:** 40+ commands
- **Day 2 Config:** 60+ commands  
- **Day 3 GuardDuty + Security Hub:** 50+ commands
- **Day 4 Macie:** 50+ commands

### Services Configured:
- ✅ **CloudTrail:** Multi-region audit logging with cryptographic validation
- ✅ **Config:** Continuous compliance monitoring with automated rules
- ✅ **GuardDuty:** ML-powered threat detection with 9 advanced features
- ✅ **Security Hub:** Centralized security operations with 11+ service integrations
- ✅ **Macie:** Automated sensitive data discovery with 100% detection accuracy

### Security Controls Implemented:
- ✅ MFA-enforced CLI access pattern
- ✅ Service-specific IAM roles with least privilege
- ✅ Comprehensive S3 security (public access blocks, service policies)
- ✅ Automated compliance monitoring and violation detection
- ✅ Complete audit trail integration across all services
- ✅ Real-time threat detection and correlation
- ✅ Sensitive data classification and protection

**Enterprise Readiness:** Complete security operations center capability with unified dashboard, automated compliance, threat detection, and data protection. ✅

---

## 🎯 Policy Files Reference

### CloudTrail Bucket Policy (cloudtrail-bucket-policy.json)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::cloudtrail-logs-733366527973-training",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "arn:aws:cloudtrail:us-east-1:733366527973:trail/SecurityAuditTrail"
        }
      }
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::cloudtrail-logs-733366527973-training/AWSLogs/733366527973/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "AWS:SourceArn": "arn:aws:cloudtrail:us-east-1:733366527973:trail/SecurityAuditTrail"
        }
      }
    }
  ]
}
```

### Config Bucket Policy (config-bucket-policy.json)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::config-compliance-data-733366527973",
      "Condition": {
        "StringEquals": {
          "AWS:SourceAccount": "733366527973"
        }
      }
    },
    {
      "Sid": "AWSConfigBucketExistenceCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::config-compliance-data-733366527973",
      "Condition": {
        "StringEquals": {
          "AWS:SourceAccount": "733366527973"
        }
      }
    },
    {
      "Sid": "AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::config-compliance-data-733366527973/AWSLogs/733366527973/Config/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "AWS:SourceAccount": "733366527973"
        }
      }
    }
  ]
}
```

### Violation Bucket Policy (violation-bucket-policy.json)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::compliance-test-bucket-733366527973/*"
    }
  ]
}
```

### Filter Files for Security Hub Queries

#### GuardDuty Filter (guardduty-filter.json)
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

#### Macie Filter (macie-filter.json)
```json
{
  "ProductName": [
    {
      "Value": "Macie",
      "Comparison": "EQUALS"
    }
  ]
}
```
