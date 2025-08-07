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

C:\Users\E114963\Downloads>ssh -i myfirstkey.pem ec2-user@34.207.250.126
   ,     #_
   ~\_  ####_        Amazon Linux 2023
  ~~  \_#####\
  ~~     \###|
  ~~       \#/ ___   https://aws.amazon.com/linux/amazon-linux-2023
   ~~       V~' '->
    ~~~         /
      ~~._.   _/
         _/ _/
       _/m/'
Last login: Thu Aug  7 05:45:22 2025 from 130.41.61.150
[ec2-user@ip-172-31-46-189 ~]$ TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)
[ec2-user@ip-172-31-46-189 ~]$ echo "Token received: $TOKEN"
Token received: AQAEAGzrZnR_yvZ5yrAVsDx1Vkbfy82jPuJxMg3tCEcOClH-vBZKAQ==
[ec2-user@ip-172-31-46-189 ~]$ curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
iamroletestingec2s3[ec2-user@ipcurl -H "X-aws-ec2-metadata-token
: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/securit
y-credentials/iamroletestingec2s3
{
  "Code" : "Success",
  "LastUpdated" : "2025-08-07T05:43:46Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA2VQANE7SUTPVYGWD",
  "SecretAccessKey" : "UJYZt+pCY5+YfNWa5M7/XwnZxlN6nDP+eofC0731",
  "Token" : "IQoJb3JpZ2luX2VjEE4aCXVzLWVhc3QtMSJHMEUCIE4aDd6z3m1S2Cw9TrIl5/Osht3BrVeVbphYGtk53/+xAiEA3OZIpLKdoRWDmfgPaXAm9HZ5GQ9QZj9JKAoecDQRwQgqxQUIh///////////ARAAGgw3MzMzNjY1Mjc5NzMiDM5hHgMVDxfVGOSorSqZBcIcGPqQdiJGyK9dV0BpBroKZeolQeSbFHsRdKqed7g3uDMu7ZPwD65etMHrptTUynd9BrlfwdoZ6BAbTo7NeukTr0DpWX4vFwAdwre48aXsenVRWNBQAhI66bWxFSZKI7zO7yCiMSsQaKhBLjqFtHXD8c2uoABwo1lSKCfS2LzRbtlpsZDiS1RPl5vyTaX7gkBSpDfF4XE3VEz4YFDS22xUSwvgauMnfWpLriZ0m7VASx33gx1TiUL+WhArNSb6MrlDbVv8zis925rMFfp9TvkuX5LDaZbZh2WAEeiRyajrfUkSges6QJPPBI82xJRaDUtNjxe0w/TTHLspoNi1VbfetbW+hxll0+1Cte7NmnXgZZxca8MAgIv4ziA0C90iIy4npDkoYoPiies0VDIBSiLarg5AvrXqj+6QWCGYlu6DJk55OZpl4AHTGeyCGm9Ip5coIRyNB45hH9EsXLiciU0HI/PS+NkA8ZsbVPgQ552cpkwYhVZ6aDs0KklaMZ/4q5JHME9q0PwHVduShZcgRP6cBOg0mskdtHmy5NqqoP0gb/09s0MJVoS4pv3Oxs8RU3q6fFtwz+wRgPU44bSstidN6GU2EEUSZ/Zi/CMTgm5wAKmQNshPuoFnRG0FwaLQAPYPaPQdRBmQ/X4HrnjWbSG9YnpqV5NJriyKcTJ2zIeNoUcEWYmk1/5KkGrBl+r+5feSIIQlFnIVNRKQuV+TZcyh/gz21LWFwwQ5xjpquCi9D1fyw/m4ca9GLd6JsgKXcnMzk+94Z+AkhuBNPcTtP5+Ka/u+J+clvbK/BAYS1Ma/6ZIZiXEKlrxT9CqyUcwagz3LhiLfUM1r25c3XuZmh79+I4KZLzJmSn0CXh+3CEowY7a6PHIBoZkkMMH60MQGOrEBHtFrQ+AqejWr9QBk7pgGslh5h8sSfPHZIwFDHIZ+BW0leOsvSBeIxRki2qW12AVfGnUfUbo4L31tFVMbSaZ/UqlHj3Ns8eYVm2grhRWHJkxbq77P/LOljaCTBkrmcGTWJQC8umhQnm6HSuZLokMrk+8zgrqajnfZO/M8WruD9/6xaUXwb3tB/R1DFKU6ieiwwCoYY1RIUl+dT9BhecK/66eEjNyUrY8nFS/S0561y8t/",
  "Expiration" : "2025-08-07T12:19:33Z"
}[ec2-user@ip-172-31-46-189 ~]$
