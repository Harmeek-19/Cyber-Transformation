# AWS Security Architecture Demos - CLI Commands Used

## 📋 Commands Used in Live Demonstrations

This document contains **only** the CLI commands actually used in the 7 AWS Security Architecture demos, organized by demonstration sequence.

---

## 🔧 Demo 1: Account Security Foundation

### Commands Used:

| Command | Purpose | Demo Context |
|---------|---------|--------------|
| `aws configure` | Configure AWS CLI with admin user credentials | Set up CLI access with admin user (not root) |
| `aws sts get-caller-identity` | Verify current user identity | Confirm we're using admin user, not root account |
| `aws configure list` | Display current configuration | Show CLI is properly configured with correct user |

### Expected Outputs:
- **`aws sts get-caller-identity`** should show admin user ARN, not root
- **`aws configure list`** should show admin user access key and us-east-1 region

---

## 👥 Demo 2: IAM Permission Control

### Commands Used:

| Command | Purpose | Demo Context |
|---------|---------|--------------|
| `aws configure --profile test-user` | Configure CLI profile for test user | Set up test user credentials for permission testing |
| `aws s3 ls --profile test-user` | Test S3 access with test user | Initially fails (no permissions), later succeeds after policy attachment |
| `aws iam list-users --profile test-user` | Test IAM access with test user | Succeeds after adding to iamreadonly group |
| `aws ec2 describe-instances --profile test-user` | Test EC2 access with test user | Always fails (proves least privilege working) |

### Permission Testing Flow:
1. **No permissions:** `aws s3 ls --profile test-user` → Access Denied ❌
2. **After IAM group:** `aws iam list-users --profile test-user` → Success ✅
3. **After S3 policy:** `aws s3 ls --profile test-user` → Success ✅
4. **EC2 still blocked:** `aws ec2 describe-instances --profile test-user` → Access Denied ❌

---

## 🎫 Demo 3: IAM Roles & Service Authentication

### Commands Used:

| Command | Purpose | Demo Context |
|---------|---------|--------------|
| `aws configure --profile neil2` | Configure CLI for role assumption testing | Set up user with no direct permissions |
| `aws s3 ls --profile neil2` | Test S3 access without role | Shows access denied before role assumption |
| `aws sts assume-role --role-arn arn:aws:iam::ACCOUNT-ID:role/iamroletests3 --role-session-name test-session --profile neil2` | Assume role to gain S3 access | Get temporary credentials with S3 permissions |
| `aws s3 ls` | Test S3 access with assumed role | Works after assuming role (using temporary credentials) |
| `aws s3 ls` | Test S3 access from EC2 instance | Demonstrates automatic role assumption by EC2 |
| `aws ec2 describe-instances` | Test EC2 access from EC2 instance | Fails because role doesn't include EC2 permissions |
| `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3` | Show temporary credentials | Display auto-rotating credentials from EC2 metadata |

Yes — the command must be run with the IP 169.254.169.254 only.

✅ Why?
This IP is hardcoded by AWS as the endpoint for the Instance Metadata Service (IMDS). It’s a special internal IP that only works inside an EC2 instance. You cannot replace it with the instance’s public or private IP.

🔐 What Happens When You Run It?
When you run:


The EC2 instance connects to the metadata service running at that IP.
It fetches temporary credentials for the IAM role named iamroleec2s3.
🧠 Quick Analogy
Think of 169.254.169.254 like a local help desk inside your EC2 instance. It’s always there, always at the same address, and only your instance can talk to it.

### Role Flow Demonstration:
1. **Before role:** `aws s3 ls --profile neil2` → Access Denied ❌
2. **Assume role:** Get temporary credentials from assume-role command
3. **With role:** `aws s3 ls` → Success ✅ (using exported temporary credentials)
4. **From EC2:** `aws s3 ls` → Success ✅ (automatic role assumption)
5. **EC2 limits:** `aws ec2 describe-instances` → Access Denied ❌ (role boundary working)

---

## 🌐 Demo 4: VPC Network Architecture

### Commands Used:

| Command | Purpose | Demo Context |
|---------|---------|--------------|
| `aws ec2 describe-vpcs --vpc-ids $VPC_ID` | Show VPC details | Display custom VPC configuration after creation |
| `aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID"` | Show subnet details | Display public and private subnets in custom VPC |
| `aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID"` | Show routing configuration | Display route tables and internet gateway routes |
| `aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID"` | Show internet gateway | Verify internet gateway is attached to VPC |

### Network Verification Flow:
- **VPC:** Shows custom CIDR block (10.0.0.0/16)
- **Subnets:** Shows public (10.0.1.0/24) and private (10.0.2.0/24) subnets
- **Routes:** Shows internet gateway route for public subnet only
- **Gateway:** Shows internet gateway attached and available

---

## 🔒 Demo 5: Network Firewall Defense

### Commands Used:

| Command | Purpose | Demo Context |
|---------|---------|--------------|
| `curl https://checkip.amazonaws.com` | Get current public IP | Determine admin IP for security group rules |
| `aws ec2 describe-security-groups --group-ids $SG_ID` | Show security group rules | Display SSH access restricted to admin IP only |
| `aws ec2 describe-network-acls --network-acl-ids $CUSTOM_NACL_ID` | Show network ACL rules | Display subnet-level firewall rules |

### Security Validation:
- **IP Discovery:** Shows current public IP for firewall rules
- **Security Group:** Shows SSH (port 22) allowed from admin IP only
- **Network ACL:** Shows inbound SSH and outbound ephemeral port rules

---

## 💻 Demo 6: Secure EC2 Launch

### Commands Used:

| Command | Purpose | Demo Context |
|---------|---------|--------------|
| `aws ec2 describe-instances --instance-ids $INSTANCE_ID` | Show instance details | Display secure instance configuration |
| `aws ec2 wait instance-running --instance-ids $INSTANCE_ID` | Wait for instance ready | Ensure instance is running before connection |

### Instance Verification:
- **Configuration:** Shows instance in custom VPC, public subnet, with security group and IAM role
- **Status:** Confirms instance is running and ready for SSH connection

---

## 🎯 Demo 7: Complete End-to-End Validation

### Commands Used (from within EC2 instance):

| Command | Purpose | Demo Context |
|---------|---------|--------------|
| `aws s3 ls` | Test S3 access from EC2 | Should work - role allows S3 read access |
| `aws s3api list-buckets` | Test detailed S3 operations | Should work - demonstrates S3 permissions |
| `aws ec2 describe-instances` | Test EC2 management from EC2 | Should fail - role doesn't include EC2 permissions |
| `aws iam list-users` | Test IAM access from EC2 | Should fail - role doesn't include IAM permissions |
| `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3` | Show instance credentials | Display temporary, auto-rotating credentials |
| `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3 | grep Expiration` | Show credential expiration | Display when credentials expire (6-hour rotation) |
| `ls -la ~/.aws/` | Check for credential files | Should show no files - proves no hardcoded credentials |
| `env | grep -i aws` | Check environment variables | Should show no AWS variables - proves no hardcoded credentials |

### Complete Validation Results:

| Test Category | Command | Expected Result | Security Proof |
|---------------|---------|----------------|-----------------|
| **Allowed Operations** | `aws s3 ls` | ✅ Success | Role permissions working |
| **Allowed Operations** | `aws s3api list-buckets` | ✅ Success | S3 access confirmed |
| **Blocked Operations** | `aws ec2 describe-instances` | ❌ Access Denied | Permission boundary enforced |
| **Blocked Operations** | `aws iam list-users` | ❌ Access Denied | Least privilege working |
| **Credential Security** | `ls -la ~/.aws/` | No files found | No hardcoded credentials |
| **Credential Security** | `env \| grep -i aws` | No variables | No environment credentials |
| **Auto-Rotation** | `curl ...security-credentials...` | Shows expiration | Credentials expire automatically |

---

## 📊 Command Summary by Category

### **Identity and Verification:**
- `aws sts get-caller-identity` - Who am I?
- `aws configure list` - How am I configured?
- `curl https://checkip.amazonaws.com` - What's my IP?

### **Permission Testing:**
- `aws s3 ls` - Do I have S3 access?
- `aws iam list-users` - Do I have IAM access?
- `aws ec2 describe-instances` - Do I have EC2 access?
- `aws s3api list-buckets` - Can I perform detailed S3 operations?

### **Role Management:**
- `aws sts assume-role` - Switch to different permissions
- `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` - Show automatic credentials

### **Infrastructure Verification:**
- `aws ec2 describe-vpcs` - Show network architecture
- `aws ec2 describe-subnets` - Show network segmentation
- `aws ec2 describe-security-groups` - Show firewall rules
- `aws ec2 describe-instances` - Show instance configuration

### **Security Validation:**
- `ls -la ~/.aws/` - Check for credential files
- `env | grep -i aws` - Check for environment credentials
- Profile-based commands with `--profile` - Test different user permissions

---

## 🎯 Key Command Patterns in Demos

### **Progressive Permission Testing:**
1. Start with no permissions → Access Denied
2. Add group membership → Some access granted  
3. Add custom policy → Additional access granted
4. Test boundaries → Other services still denied

### **Role-Based Authentication:**
1. Direct user access → Fails without permissions
2. Assume role → Temporary access granted
3. EC2 automatic assumption → Seamless service access
4. Permission boundaries → Only specific services allowed

### **Security Verification:**
1. Network access → SSH from authorized IP only
2. Service permissions → Only S3 read access works
3. Credential security → No hardcoded keys found
4. Automatic rotation → Credentials expire and refresh

---

## 📝 Notes for Demo Execution

### **Variable Usage:**
- Replace `$VPC_ID`, `$SG_ID`, `$INSTANCE_ID` with actual values during demos
- Replace `ACCOUNT-ID` with your actual AWS account ID
- Replace `--profile` names with your configured profile names

### **Expected Failures:**
- Many commands are **supposed to fail** to demonstrate security boundaries
- Access Denied errors are **positive results** showing security is working
- Missing credential files are **good signs** showing no hardcoded keys

### **Success Indicators:**
- `aws sts get-caller-identity` showing admin user (not root)
- S3 commands working when permissions allow
- EC2/IAM commands failing when permissions deny
- Temporary credentials showing expiration times

Perfect! I can see exactly what's happening. Your setup is working correctly, but there are two issues:

## **🎯 Great News: Your Setup is Working!**

Looking at your output, I can see:

1. **✅ IAM Role is attached:** `"IamInstanceProfile": { "Arn": "arn:aws:iam::733366527973:instance-profile/iamroletestingec2s3"`
2. **✅ S3 access works:** `aws s3 ls` successfully listed your buckets
3. **✅ No hardcoded credentials:** The role is providing access automatically

## **🔍 Two Issues to Fix:**

### **Issue 1: IMDSv2 is Required**

In your instance metadata, I see:
```json
"HttpTokens": "required"
```

This means your instance requires **IMDSv2** (Instance Metadata Service version 2), which needs a token for security.

### **Issue 2: Wrong Role Name in URL**

Your instance profile is named `iamroletestingec2s3`, but you need to check what the actual **role name** is inside that profile.

## **🛠️ Solutions:**

### **Step 1: Use IMDSv2 to Access Metadata**

SSH back into your EC2 instance and run:

```bash
# Get a token first (required for IMDSv2)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)

# Check if we got a token
echo "Token received: $TOKEN"

# Use token to get available credential names
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

This should return the actual role name.

### **Step 2: Get the Credentials**

Once you get the role name from Step 1, use it:

```bash
# Use the actual role name returned from previous command
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/[ACTUAL-ROLE-NAME]
```

### **Step 3: Check Instance Profile Contents (From Local Machine)**

From your Windows machine, check what role is actually in the instance profile:

```powershell
aws iam get-instance-profile --instance-profile-name iamroletestingec2s3
```

This will show you the exact role name inside the instance profile.

## **🎯 For Your Demo - Working Commands:**

Here's what you should use in your presentation:

```bash
# SSH into EC2 instance
ssh -i myfirstkey.pem ec2-user@34.207.250.126

# Show S3 access works (this proves the role is working)
aws s3 ls

# Show no hardcoded credentials
ls -la ~/.aws/
env | grep -i aws

# Get metadata token (required for this instance)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)

# Show available credentials
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get actual credentials (use role name from above)
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]

# Test permission boundaries
aws ec2 describe-instances  # Should fail
aws iam list-users          # Should fail
```

## **💡 Key Demo Points:**

### **What's Working Perfectly:**
1. **✅ Role attachment:** Instance profile is properly attached
2. **✅ S3 access:** `aws s3 ls` works without any credential files
3. **✅ Security:** No hardcoded credentials anywhere
4. **✅ IMDSv2:** Your instance is using the more secure metadata service

### **For Your Presentation:**
> *"Notice that S3 access works perfectly even though we have no credential files. The IAM role provides temporary, auto-rotating credentials that are managed entirely by AWS. This instance is also using IMDSv2, which is the more secure version of the metadata service that requires token-based authentication."*

## **🚀 Demo Script:**

```bash
# 1. Show S3 works
aws s3 ls
echo "✅ S3 access working with IAM role"

# 2. Show no credentials stored
ls -la ~/.aws/ 2>/dev/null || echo "✅ No credential files found"
env | grep -i aws || echo "✅ No AWS environment variables"

# 3. Show temporary credentials (with IMDSv2)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)
echo "Role name available:"
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 4. Show permission boundaries work
aws ec2 describe-instances && echo "❌ This should have failed!" || echo "✅ EC2 access properly denied"
```

Your setup is actually working perfectly - you just need to use IMDSv2 to access the metadata!
