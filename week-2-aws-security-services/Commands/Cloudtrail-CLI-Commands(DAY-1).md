# Day 2: AWS Config - CLI Commands Reference

## Environment Setup

🔧 Environment Setup
Prerequisites Verification
# Verify AWS CLI profile and MFA setup
aws sts get-caller-identity --profile admin-mfa
# Expected: Shows assumed-role/AdminRole-MFA in account 733366527973
PowerShell Environment Setup
# Set environment variable for PowerShell sessions
$env:AWS_PROFILE = "admin-mfa"

# Verify identity and MFA access
aws sts get-caller-identity
Working Directory Setup
# Create organized workspace
mkdir aws-security-services
cd aws-security-services
mkdir policy-files
mkdir logs
🔍 DAY 1: CLOUDTRAIL - AUDIT LOGGING FOUNDATION
S3 Bucket Setup for CloudTrail
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
CloudTrail Configuration
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
Security Event Generation for Testing
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
CloudTrail Log Analysis
# Download CloudTrail logs for analysis
aws s3 sync s3://cloudtrail-logs-733366527973-training/AWSLogs/733366527973/CloudTrail/us-east-1/2025/08/14/ ./cloudtrail-logs/ --profile admin-mfa

# Search for specific events (Windows)
findstr /S /I "CreateBucket" cloudtrail-logs\*.json
findstr /S /I "configservice" cloudtrail-logs\*.json
findstr /S /I "GetCallerIdentity" cloudtrail-logs\*.json
