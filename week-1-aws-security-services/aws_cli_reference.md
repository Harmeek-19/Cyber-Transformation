# AWS Security Architecture - Demo CLI Commands Reference

This repository contains all the CLI commands I actually used during my 7 AWS Security Architecture demonstrations. These are real commands that I ran and tested, organized by demo sequence for easy reference.

## 🚀 Quick Start

If you're following along with these demos, make sure you have:
- AWS CLI installed and configured
- Appropriate IAM permissions 
- A basic understanding of AWS networking concepts

> **Note**: All commands in this guide have been tested and work as documented. If you run into issues, check the troubleshooting section at the bottom.

---

## 🔒 Understanding Instance Metadata Service (IMDS)

One thing I learned the hard way during these demos is that modern EC2 instances use **IMDSv2** by default for security. This means you need to authenticate with a token before accessing instance metadata.

### Why This Matters

Modern AWS instances require token-based authentication to prevent Server-Side Request Forgery (SSRF) attacks. Here's what you need to know:

| Approach | Legacy (IMDSv1) | Modern (IMDSv2) |
|----------|-----------------|-----------------|
| **Token Required** | No | Yes |
| **Command Example** | `curl http://169.254.169.254/latest/meta-data/` | First get token, then use it in headers |
| **Security Level** | Basic | Enhanced |

### How to Get Credentials from EC2 Instances

```bash
# Step 1: Get authentication token (lasts 6 hours)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)

# Step 2: Use token to access metadata
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 3: Get actual credentials
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
```

**Why this is secure**: The two-step process ensures only legitimate applications can access credentials, and tokens expire automatically.

---

## 🔧 Demo 1: Account Security Foundation

The first demo focuses on setting up secure AWS CLI access using an admin user instead of the root account.

### Commands I Used

| What I Did | Command | Why This Matters |
|------------|---------|------------------|
| Configure AWS CLI | `aws configure` | Sets up CLI with admin user credentials (never use root for daily tasks) |
| Verify identity | `aws sts get-caller-identity` | Confirms I'm using admin user, not root account |
| Check configuration | `aws configure list` | Shows CLI is properly configured with correct region |

### What Success Looks Like

When you run `aws sts get-caller-identity`, you should see something like:
```json
{
    "UserId": "AIDAXXXXXXXXXXXXX",
    "Account": "123456789012", 
    "Arn": "arn:aws:iam::123456789012:user/admin-user"
}
```

**Key point**: The ARN should show a user, not root. This proves you're following security best practices.

---

## 👥 Demo 2: IAM Permission Control

This demo shows how to implement least privilege access by progressively granting permissions to a test user.

### The Permission Journey

I created a test user and watched their permissions evolve:

| Step | Command | Expected Result | What This Proves |
|------|---------|----------------|------------------|
| **Initial State** | `aws s3 ls --profile test-user` | ❌ Access Denied | Users start with zero permissions |
| **After Group Assignment** | `aws iam list-users --profile test-user` | ✅ Success | Group-based permissions work |
| **After Custom Policy** | `aws s3 ls --profile test-user` | ✅ Success | Custom policies provide specific access |
| **Boundary Test** | `aws ec2 describe-instances --profile test-user` | ❌ Access Denied | Least privilege is working |

### Setting Up the Test

```bash
# Configure test user profile
aws configure --profile test-user
# Enter the test user's access keys when prompted
```

### Key Learning

The beauty of this approach is that you can see permissions in action. The user literally goes from having no access to having exactly the access they need - nothing more, nothing less.

---

## 🎫 Demo 3: IAM Roles & Service Authentication

This is where things get really interesting. IAM roles eliminate the need for hardcoded credentials entirely.

### Two Types of Role Usage

**User Role Assumption** (Temporary permission elevation):
```bash
# Test access without role
aws s3 ls --profile neil2  # Fails ❌

# Assume role temporarily  
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT-ID:role/iamroletests3 \
  --role-session-name test-session \
  --profile neil2

# Export the temporary credentials from the output above
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Now S3 access works
aws s3 ls  # Success ✅
```

**EC2 Service Roles** (Automatic authentication):
```bash
# From within an EC2 instance with an attached role
aws s3 ls  # Works automatically ✅
aws ec2 describe-instances  # Fails (not in role permissions) ❌
```

### Viewing Automatic Credentials

From inside an EC2 instance, you can see the temporary credentials AWS provides:

```bash
# Get metadata token first
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)

# See available roles
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get the actual credentials  
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3
```

**What makes this secure**: Credentials rotate automatically every 6 hours, and there's no way to extract long-term keys.

---

## 🌐 Demo 4: VPC Network Architecture

After setting up the VPC through the console, I used these commands to verify everything was configured correctly.

### Verification Commands

```bash
# Check VPC configuration
aws ec2 describe-vpcs --vpc-ids $VPC_ID

# Verify subnet setup  
aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID"

# Check routing
aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID"

# Verify internet gateway
aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID"
```

### What to Look For

- **VPC**: Custom CIDR block (10.0.0.0/16)
- **Subnets**: Public (10.0.1.0/24) and private (10.0.2.0/24) 
- **Routes**: Internet gateway route for public subnet only
- **Gateway**: Shows as "attached" and "available"

---

## 🔒 Demo 5: Network Firewall Defense

This demo taught me the most about AWS networking security. I'll share what actually works in practice.

### What I Actually Use

```bash
# Get my current IP for security rules
curl https://checkip.amazonaws.com

# Check security group configuration
aws ec2 describe-security-groups --group-ids $SG_ID

# Verify network ACL rules (if using custom NACLs)
aws ec2 describe-network-acls --network-acl-ids $CUSTOM_NACL_ID
```

### Real-World Lesson Learned

**Security Groups vs NACLs**: After testing both approaches extensively, I recommend using Security Groups as your primary defense. Here's why:

- **Security Groups are stateful** - they automatically handle return traffic
- **NACLs are stateless** - you have to manually configure both directions
- **Security Groups are simpler** - fewer rules to manage and less chance of mistakes

**When to use NACLs**: Subnet-level policies, compliance requirements, or emergency isolation. For most use cases, Security Groups + default NACLs work perfectly.

---

## 💻 Demo 6: Secure EC2 Launch

These commands help verify your EC2 instance launched with proper security configurations.

### Post-Launch Verification

```bash
# Check instance details
aws ec2 describe-instances --instance-ids $INSTANCE_ID

# Wait for instance to be ready
aws ec2 wait instance-running --instance-ids $INSTANCE_ID
```

### What to Verify

- Instance is in your custom VPC
- Security group is attached
- IAM role is attached
- Instance has a public IP (if in public subnet)

---

## 🎯 Demo 7: Complete End-to-End Validation

This is where everything comes together. These commands are run from within the EC2 instance to prove the security is working.

### Security Validation Commands

```bash
# Test what should work
aws s3 ls  # ✅ Should succeed
aws s3api list-buckets  # ✅ Should succeed

# Test what should fail  
aws ec2 describe-instances  # ❌ Should fail (not in role)
aws iam list-users  # ❌ Should fail (not in role)
```

### Credential Security Check

```bash
# Verify no hardcoded credentials
ls -la ~/.aws/  # Should show no files
env | grep -i aws  # Should show no AWS variables

# Show temporary credentials are working
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)

curl -H "X-aws-ec2-metadata-token: $TOKEN" -s \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3

# Check when credentials expire
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3 | grep Expiration
```

### What This Proves

| Test | Expected Result | Security Proof |
|------|----------------|----------------|
| S3 access | ✅ Works | Role permissions are functional |
| EC2 management | ❌ Blocked | Permission boundaries are enforced |
| Credential files | None found | No hardcoded credentials anywhere |
| Auto-rotation | Shows expiration | Credentials refresh automatically |

---

## 📊 Command Patterns I Found Useful

### Identity and Verification
```bash
aws sts get-caller-identity  # Who am I?
aws configure list           # How am I configured?
curl https://checkip.amazonaws.com  # What's my IP?
```

### Permission Testing
```bash
aws s3 ls                    # Do I have S3 access?
aws iam list-users          # Do I have IAM access?  
aws ec2 describe-instances  # Do I have EC2 access?
```

### Role Management
```bash
aws sts assume-role         # Switch to different permissions

# Get secure metadata token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)

# Show automatic credentials
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## 🛠️ Troubleshooting Tips

### Common Issues I Encountered

**IMDSv2 Token Issues**: If metadata commands hang or fail, you're probably on a modern instance that requires tokens. Always use the token-based approach shown above.

**Permission Denied Errors**: These are often good signs! They prove your security boundaries are working. Make sure you understand which commands should fail.

**Profile Configuration**: When using `--profile`, make sure you've configured that profile with `aws configure --profile [name]` first.

### Variables to Replace

Throughout these commands, replace these placeholders with your actual values:
- `$VPC_ID` - Your VPC ID
- `$SG_ID` - Your Security Group ID  
- `$INSTANCE_ID` - Your EC2 Instance ID
- `ACCOUNT-ID` - Your AWS Account ID
- `[ROLE-NAME]` - Your actual IAM role name

### When Commands Should Fail

Remember, many of these commands are **supposed to fail** - that's how we prove security is working:
- Access Denied errors show permission boundaries are enforced
- Missing credential files prove no hardcoded keys exist
- Failed EC2/IAM commands from EC2 instances prove least privilege

---

## 🎓 Key Takeaways

After working through all these demos, here's what I learned:

1. **IMDSv2 is the new standard** - Always use token-based metadata access
2. **Security Groups are usually sufficient** - Default NACLs work great for most cases
3. **Roles eliminate credential management** - No keys to rotate or secure
4. **Stateful firewalls are simpler** - Let AWS handle the complexity
5. **Failed commands can be success** - Proves your security is working

These commands represent real-world, tested approaches to AWS security. They follow current best practices and work reliably in production environments.

---

