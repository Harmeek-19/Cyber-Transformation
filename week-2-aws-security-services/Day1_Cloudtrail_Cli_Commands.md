# Day 1: CloudTrail CLI Commands Reference

## Environment Setup

### Initial Identity Verification
```bash
# 1. Verify initial AWS CLI connection
aws sts get-caller-identity
# Expected output: Shows IAM user admin in account 733366527973
# Achievement: Confirms CLI authentication and correct AWS account connection
```

### MFA Session Token Implementation
```bash
# 2. Request temporary MFA credentials (12-hour session)
aws sts get-session-token \
  --serial-number arn:aws:iam::733366527973:mfa/device-1 \
  --token-code 138559 \
  --duration-seconds 43200

# Expected output: JSON with AccessKeyId, SecretAccessKey, SessionToken
# Achievement: Obtained temporary credentials required for secure role assumption
```

### Testing Base User Permissions
```bash
# 3. Test S3 access with base IAM user
aws s3 ls
# Expected result: Access denied (s3:ListAllMyBuckets permission missing)
# Learning: Demonstrates principle of least privilege - base user has minimal permissions
```

### Profile Configuration Setup
```bash
# 4. Configure named profile for MFA credentials
aws configure --profile admin-mfa
# Manual step: Enter temporary credentials from step 2

# 5. Edit configuration files manually
notepad %USERPROFILE%\.aws\config
notepad %USERPROFILE%\.aws\credentials
# Achievement: Set up profile structure for secure role assumption
```

### Credential File Troubleshooting
```bash
# 6. Test admin-base profile (initially failed)
aws --profile admin-base sts get-caller-identity
# Initial error: "Unable to locate credentials"
# Resolution: Corrected credentials file configuration

# 7. Test role assumption (with MFA prompt)
aws --profile admin-mfa sts get-caller-identity
# Initial error: Access denied for sts:AssumeRole
# Success after MFA: Shows assumed-role/AdminRole-MFA ARN
# Achievement: Successfully transitioned from IAM user to elevated role
```

### Environment Variable Management
```bash
# 8. Set default profile for convenience
set AWS_PROFILE=admin-mfa
# Achievement: Eliminates need to specify --profile for each command

# 9. Clear environment variable (Windows syntax learning)
# Incorrect: unset AWS_PROFILE (Linux/Mac syntax)
# Correct for Windows: set AWS_PROFILE=
```

### Final MFA Profile Verification
```bash
# 10. Verify secure profile setup
aws sts get-caller-identity
# Expected output:
# {
#     "UserId": "AROA2VQANE7STGEAS3VBI:botocore-session-1755065747",
#     "Account": "733366527973", 
#     "Arn": "arn:aws:sts::733366527973:assumed-role/AdminRole-MFA/botocore-session-1755065747"
# }
# Achievement: Confirmed secure access with MFA-enforced role assumption
```

**Key Learning Outcomes from Setup:**
- **Identity Verification:** Confirmed CLI connection and account access
- **MFA Implementation:** Successfully obtained and used temporary credentials
- **Permission Testing:** Demonstrated least privilege principle with base user
- **Profile Management:** Configured secure profile structure for role assumption
- **Error Resolution:** Resolved credential configuration and permission issues
- **Security Achievement:** Established MFA-enforced administrative access

---

## Phase 1: S3 Bucket Setup (Secure Log Storage)

### Create CloudTrail Logs Bucket
```bash
# Create dedicated S3 bucket for CloudTrail logs
aws s3 mb s3://cloudtrail-logs-733366527973-training --region us-east-1
# Expected output: make_bucket: cloudtrail-logs-733366527973-training
# Achievement: Successful bucket creation after resolving help command usage
```

**Learning Note:** Initially attempted `aws s3 --help` to understand S3 commands. Successfully created bucket after understanding proper CLI syntax.

**Purpose:** Creates secure storage location for audit logs with account-specific naming to ensure global uniqueness.

### Apply Security Controls
```bash
# Block all public access (critical security requirement)
aws s3api put-public-access-block \
  --bucket cloudtrail-logs-733366527973-training \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Expected output: No output (success is silent)
```

**Common Error Resolution:**
```bash
# Initial attempt with incorrect parameter casing (FAILED):
aws s3api put-public-access-block \
  --bucket cloudtrail-logs-733366527973-training \
  --public-access-block-configuration "BlockPublicACLs=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Error: Parameter validation failed due to incorrect casing
# Learning: AWS CLI parameter names are case-sensitive
# Correct parameter: BlockPublicAcls (not BlockPublicACLs)
```

**Security Purpose:** 
- **BlockPublicAcls=true:** Prevents new public ACLs
- **IgnorePublicAcls=true:** Ignores existing public ACLs
- **BlockPublicPolicy=true:** Prevents public bucket policies
- **RestrictPublicBuckets=true:** Restricts public bucket access

**Why Critical:** Audit logs contain sensitive information (IP addresses, user identities, resource names) that must never be publicly accessible.

### Verify Security Configuration
```bash
# Confirm public access controls are applied
aws s3api get-public-access-block --bucket cloudtrail-logs-733366527973-training

# Expected output: JSON showing all 4 public access blocks set to true
```

---

## Phase 2: CloudTrail Service Permissions

### Problem Resolution: InsufficientS3BucketPolicyException
**Error Encountered:**
```
An error occurred (InsufficientS3BucketPolicyException) when calling the CreateTrail operation: 
Incorrect S3 bucket policy is detected for bucket: cloudtrail-logs-733366527973-training
```

**Root Cause:** Public access block prevents CloudTrail from automatically configuring bucket access.

**Solution:** Manually apply CloudTrail-specific bucket policy.

### Apply CloudTrail Bucket Policy
```bash
# Method 1: Create policy file first
# Create cloudtrail-bucket-policy.json with required permissions

# Method 2: Apply policy using S3 API (CORRECT command)
aws s3api put-bucket-policy \
  --bucket cloudtrail-logs-733366527973-training \
  --policy file://cloudtrail-bucket-policy.json

# Expected output: No output (success is silent)
```

**Required Policy Content (cloudtrail-bucket-policy.json):**
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

### Verify Bucket Policy Application
```bash
# Confirm policy was applied correctly
aws s3api get-bucket-policy --bucket cloudtrail-logs-733366527973-training

# Expected output: JSON showing the applied CloudTrail policy
```

**Security Analysis:**
- **s3:GetBucketAcl:** CloudTrail verifies bucket configuration
- **s3:PutObject:** CloudTrail writes log files to bucket
- **SourceArn condition:** Only our specific trail can access the bucket
- **bucket-owner-full-control:** Ensures account owner retains full control of audit logs

---

## Phase 3: CloudTrail Configuration

### Create Multi-Region Trail with Security Features
```bash
# Create trail with comprehensive security configuration
aws cloudtrail create-trail \
  --name SecurityAuditTrail \
  --s3-bucket-name cloudtrail-logs-733366527973-training \
  --include-global-service-events \
  --is-multi-region-trail \
  --enable-log-file-validation

# Expected output: JSON with trail configuration including TrailARN
```

**Parameter Breakdown:**
- **--name SecurityAuditTrail:** Human-readable identifier for the trail
- **--s3-bucket-name:** Destination for log files (our secured bucket)
- **--include-global-service-events:** Captures IAM, STS, CloudFront events (critical for security)
- **--is-multi-region-trail:** Logs events from ALL AWS regions in one centralized location
- **--enable-log-file-validation:** Enables cryptographic integrity checking (SHA-256 + digital signatures)

**Enterprise Security Value:**
- **Complete coverage:** No AWS region activity is unmonitored
- **Identity monitoring:** All authentication and authorization events captured
- **Forensic readiness:** Log integrity can be cryptographically verified for legal evidence

### Start Active Logging
```bash
# Activate the trail to begin capturing events
aws cloudtrail start-logging --name SecurityAuditTrail

# Expected output: No output (success is silent)
```

### Verify Trail Status and Configuration
```bash
# Check if trail is actively logging
aws cloudtrail get-trail-status --name SecurityAuditTrail

# Expected output: JSON showing IsLogging: true, StartLoggingTime, no errors
```

```bash
# Verify trail configuration details
aws cloudtrail describe-trails --trail-name-list SecurityAuditTrail

# Expected output: Complete trail configuration including all security settings
```

**Key Status Indicators:**
- **IsLogging: true** - Trail is actively capturing events
- **LatestDeliveryTime** - When logs were last delivered to S3
- **StartLoggingTime** - When logging was activated
- **No errors** - Trail is functioning properly

---

## Phase 4: Security Event Generation

### Generate Diverse Security Events for Analysis
```bash
# 1. Identity verification events
aws sts get-caller-identity
# Creates: GetCallerIdentity event showing role assumption

# 2. IAM enumeration events (reconnaissance patterns)
aws iam list-users
aws iam list-roles
# Creates: ListUsers, ListRoles events showing account discovery

# 3. S3 service interaction events
aws s3 ls
aws s3api list-buckets
# Creates: ListBuckets events showing data discovery patterns

# 4. CloudTrail management events
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name SecurityAuditTrail
# Creates: DescribeTrails, GetTrailStatus events showing configuration queries

# 5. Resource lifecycle events (create/delete patterns)
aws s3 mb s3://test-event-bucket-733366527973 --region us-east-1
aws s3 rb s3://test-event-bucket-733366527973 --region us-east-1
# Creates: CreateBucket, DeleteBucket events showing infrastructure changes

# 6. Additional identity events
aws iam get-user --user-name admin
# Creates: GetUser event showing user information access
```

**Event Categories Generated:**
- **Authentication:** Role assumptions and identity verification
- **Authorization:** Permission and access pattern checks
- **Resource Discovery:** Enumeration of users, roles, buckets
- **Infrastructure Changes:** Resource creation and deletion
- **Configuration Queries:** Service status and configuration checks

**Security Analysis Value:**
- **Normal Patterns:** Establishes baseline for legitimate administrative activity
- **Attack Patterns:** Similar commands used by attackers for reconnaissance
- **Forensic Evidence:** Complete audit trail of account activity for incident response

---

## Phase 5: Log Analysis and Verification

### Check Log Delivery Status
```bash
# Verify logs are being delivered to S3 (wait 10-15 minutes after event generation)
aws s3 ls s3://cloudtrail-logs-733366527973-training/ --recursive

# Expected output: Directory structure with today's date and log files
# Example: AWSLogs/733366527973/CloudTrail/us-east-1/2025/08/13/
```

### Download Logs for Analysis
```bash
# Create local directory for log analysis
mkdir cloudtrail-logs

# Download today's log files for examination
aws s3 sync s3://cloudtrail-logs-733366527973-training/AWSLogs/733366527973/CloudTrail/us-east-1/2025/08/13/ ./cloudtrail-logs/

# Expected output: Downloaded .json.gz files containing compressed event logs
```

### List Downloaded Log Files
```bash
# Examine downloaded log files
dir cloudtrail-logs
# or
ls cloudtrail-logs

# Expected output: Files named like: 733366527973_CloudTrail_us-east-1_20250813T1234Z_AbCdEf123456.json.gz
```

**Log File Structure:**
- **Compressed Format:** .json.gz files for storage efficiency
- **Timestamp Naming:** Shows when logs were created and delivered
- **Account ID:** Identifies source AWS account
- **Region:** Shows source region for the events
- **Unique Identifier:** Prevents file conflicts and enables tracking

---

## Troubleshooting Reference

### Common Errors and Solutions

#### InsufficientS3BucketPolicyException
**Error:** `Incorrect S3 bucket policy is detected for bucket`
**Cause:** Public access block prevents CloudTrail from auto-configuring access
**Solution:** Apply explicit CloudTrail bucket policy before trail creation

#### Access Denied Errors
**Error:** `User: ... is not authorized to perform: cloudtrail:CreateTrail`
**Cause:** Insufficient IAM permissions
**Solution:** Verify AdminRole-MFA is being used with correct permissions

#### MFA Token Required
**Prompt:** `Enter MFA code for arn:aws:iam::733366527973:mfa/device-1:`
**Cause:** MFA session expired or required for role assumption
**Solution:** Enter current 6-digit MFA code from authenticator app

#### Parameter Validation Failed
**Error:** `Parameter validation failed` for put-public-access-block
**Cause:** Incorrect parameter casing (BlockPublicACLs vs BlockPublicAcls)
**Solution:** Use exact AWS CLI parameter names with correct case sensitivity
**Learning:** AWS CLI parameters are strictly case-sensitive

### Verification Commands
```bash
# Verify environment setup
aws sts get-caller-identity
# Should show: assumed-role/AdminRole-MFA

# Verify bucket security
aws s3api get-public-access-block --bucket cloudtrail-logs-733366527973-training
# Should show: All 4 public access blocks = true

# Verify trail status
aws cloudtrail get-trail-status --name SecurityAuditTrail
# Should show: IsLogging = true, no errors

# Verify log delivery
aws s3 ls s3://cloudtrail-logs-733366527973-training/ --recursive
# Should show: Log files with recent timestamps
```

---

## Cost Management Notes

### CloudTrail Costs
- **Management Events (our configuration):** First copy FREE per region
- **Data Events:** Not enabled (would incur additional costs)
- **Insight Events:** Not enabled (would incur additional costs)

### S3 Storage Costs
- **Log Storage:** Standard S3 pricing (~$0.023 per GB)
- **Expected Volume:** Minimal for training account (~$0.05-0.20 for Week 2)
- **Data Transfer:** CloudTrail to S3 is FREE

### Cost Optimization
```bash
# Stop logging after training (optional)
aws cloudtrail stop-logging --name SecurityAuditTrail

# Restart for demonstrations
aws cloudtrail start-logging --name SecurityAuditTrail
```

**Recommendation:** Keep running through Week 2 for GuardDuty and Security Hub integration.

---

## Integration Notes for Days 2-4

### CloudTrail Dependencies
- **GuardDuty (Day 3):** Analyzes CloudTrail logs for threat detection
- **Security Hub (Day 3):** Aggregates CloudTrail findings with other services
- **Config (Day 2):** May reference CloudTrail for configuration change tracking

### Data Flow
```
CloudTrail Events → S3 Bucket → GuardDuty Analysis → Security Hub Aggregation
                              → Config Integration → Compliance Reporting
```

**Important:** Keep CloudTrail logging active throughout Week 2 for complete service integration demonstration.

---

## Summary - Day 1 Accomplishments

### Infrastructure Established ✅
- Secure S3 bucket with comprehensive access controls
- CloudTrail trail configured with enterprise security features
- Multi-region coverage with global service event capture
- Log file validation enabled for forensic integrity

### Security Events Generated ✅
- Identity and authentication patterns
- Resource discovery and enumeration
- Infrastructure lifecycle management
- Configuration and status queries

### Analysis Foundation ✅
- Event logs successfully delivered to S3
- Console Event History showing filtered major events
- Raw log files available for comprehensive analysis
- Integration readiness for remaining Week 2 services

### Key Learning Outcomes ✅
- **Console Event History shows filtered view** (resource-changing events)
- **Raw CloudTrail logs contain complete audit trail** including read-only events
- **Enterprise security analysis requires raw log processing**, not just console views
- **CloudTrail provides comprehensive foundation** for AWS security monitoring
- **MFA implementation is critical** for secure AWS CLI access
- **Profile management enables secure role assumption** patterns
- **AWS CLI parameter names are case-sensitive** and require exact syntax
- **Environment variable management differs** between Windows and Linux/Mac
- **Principle of least privilege demonstrated** through base user permission testing
- **Error resolution skills developed** through troubleshooting various CLI issues

**Status:** Day 1 CloudTrail implementation complete and ready for Week 2 service integration.