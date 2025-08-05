# AWS Security Architecture - CLI Commands Reference

## 📋 Complete Command Reference for All Demos

This document provides a comprehensive reference of all AWS CLI commands used across the 7 security architecture demos, organized by service and use case.

---

## 🔧 AWS CLI Configuration Commands

### Initial Setup and Configuration

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws --version` | **Environment Check** | Verify AWS CLI is installed and check version |
| `aws configure` | **Initial Setup** | Configure AWS CLI with access keys, region, and output format |
| `aws configure --profile test-user` | **Multiple Profiles** | Configure additional profiles for different users or environments |
| `aws configure list` | **Configuration Verification** | Display current AWS CLI configuration settings |
| `aws sts get-caller-identity` | **Identity Verification** | Show currently authenticated user/role and account ID |

### Profile Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws s3 ls --profile test-user` | **Profile Usage** | Execute commands using specific profile credentials |
| `aws configure --profile neil2` | **User-Specific Config** | Set up configuration for different IAM users |

---

## 👥 IAM (Identity and Access Management) Commands

### User Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws iam create-user --user-name admin-user` | **Admin User Creation** | Create new IAM user for administrative tasks |
| `aws iam create-user --user-name test-user` | **Test User Creation** | Create user for permission testing and validation |
| `aws iam delete-user --user-name test-user` | **User Cleanup** | Remove IAM user (must remove all attached policies first) |
| `aws iam list-users` | **User Inventory** | List all IAM users in the account |

### Login Profile Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws iam create-login-profile --user-name admin-user --password AdminPass123! --no-password-reset-required` | **Console Access Setup** | Enable AWS Console login for user with specified password |
| `aws iam delete-login-profile --user-name test-user` | **Console Access Removal** | Remove console login capability from user |

### Access Key Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws iam create-access-key --user-name admin-user` | **Programmatic Access** | Generate access key and secret for CLI/API access |
| `aws iam list-access-keys --user-name test-user` | **Key Inventory** | List all access keys for a specific user |
| `aws iam delete-access-key --user-name test-user --access-key-id AKIAXXXXX` | **Key Cleanup** | Remove specific access key from user |

### Group Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws iam create-group --group-name iamreadonly` | **Permission Grouping** | Create group for organizing users with similar permissions |
| `aws iam add-user-to-group --group-name iamreadonly --user-name test-user` | **Group Membership** | Add user to group to inherit group permissions |
| `aws iam remove-user-from-group --group-name iamreadonly --user-name test-user` | **Group Removal** | Remove user from group |
| `aws iam delete-group --group-name iamreadonly` | **Group Cleanup** | Delete group (must remove all users and policies first) |

### Policy Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws iam attach-user-policy --user-name admin-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` | **AWS Managed Policy** | Attach AWS-provided policy directly to user |
| `aws iam attach-group-policy --group-name iamreadonly --policy-arn arn:aws:iam::aws:policy/IAMReadOnlyAccess` | **Group Policy Attachment** | Attach AWS managed policy to group |
| `aws iam create-policy --policy-name iampolicytests3full --policy-document file://s3-read-policy.json` | **Custom Policy Creation** | Create custom policy from JSON document |
| `aws iam attach-user-policy --user-name test-user --policy-arn arn:aws:iam::ACCOUNT-ID:policy/iampolicytests3full` | **Custom Policy Attachment** | Attach custom policy to user |
| `aws iam detach-user-policy --user-name test-user --policy-arn arn:aws:iam::ACCOUNT-ID:policy/iampolicytests3full` | **Policy Detachment** | Remove policy from user |
| `aws iam delete-policy --policy-arn arn:aws:iam::ACCOUNT-ID:policy/iampolicytests3full` | **Policy Cleanup** | Delete custom policy |

### Role Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws iam create-role --role-name iamroletests3 --assume-role-policy-document file://user-trust-policy.json` | **User Role Creation** | Create role that users can assume temporarily |
| `aws iam create-role --role-name iamroleec2s3 --assume-role-policy-document file://ec2-trust-policy.json` | **Service Role Creation** | Create role for AWS services (like EC2) to assume |
| `aws iam attach-role-policy --role-name iamroleec2s3 --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess` | **Role Permission** | Grant permissions to role |
| `aws iam get-role --role-name iamroleec2s3` | **Role Information** | View role details and trust policy |
| `aws iam list-attached-role-policies --role-name iamroleec2s3` | **Role Policy Audit** | List all policies attached to role |
| `aws iam delete-role --role-name iamroleec2s3` | **Role Cleanup** | Delete role (must detach policies first) |

### Instance Profile Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws iam create-instance-profile --instance-profile-name ec2-s3-profile` | **EC2 Role Container** | Create container for EC2 role attachment |
| `aws iam add-role-to-instance-profile --instance-profile-name ec2-s3-profile --role-name iamroleec2s3` | **Role Assignment** | Add role to instance profile for EC2 use |
| `aws iam remove-role-from-instance-profile --instance-profile-name ec2-s3-profile --role-name iamroleec2s3` | **Role Removal** | Remove role from instance profile |
| `aws iam delete-instance-profile --instance-profile-name ec2-s3-profile` | **Profile Cleanup** | Delete instance profile |

### Role Assumption

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws sts assume-role --role-arn arn:aws:iam::ACCOUNT-ID:role/iamroletests3 --role-session-name test-session --profile neil2` | **Temporary Access** | Assume role to get temporary credentials with role permissions |

---

## 🌐 VPC (Virtual Private Cloud) Commands

### VPC Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws ec2 create-vpc --cidr-block 10.0.0.0/16` | **Custom Network** | Create isolated virtual network with specified IP range |
| `aws ec2 describe-vpcs --vpc-ids vpc-xxxxxxxx` | **VPC Information** | Get details about specific VPC |
| `aws ec2 modify-vpc-attribute --vpc-id vpc-xxxxxxxx --enable-dns-hostnames` | **DNS Configuration** | Enable hostname resolution within VPC |
| `aws ec2 delete-vpc --vpc-id vpc-xxxxxxxx` | **VPC Cleanup** | Delete VPC (must remove all resources first) |

### Subnet Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws ec2 create-subnet --vpc-id vpc-xxxxxxxx --cidr-block 10.0.1.0/24 --availability-zone us-east-1a` | **Network Segmentation** | Create subnet within VPC for resource placement |
| `aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-xxxxxxxx"` | **Subnet Inventory** | List all subnets in specific VPC |
| `aws ec2 modify-subnet-attribute --subnet-id subnet-xxxxxxxx --map-public-ip-on-launch` | **Public IP Assignment** | Enable automatic public IP for instances in subnet |
| `aws ec2 delete-subnet --subnet-id subnet-xxxxxxxx` | **Subnet Cleanup** | Delete subnet |

### Internet Gateway Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws ec2 create-internet-gateway` | **Internet Access** | Create gateway for internet connectivity |
| `aws ec2 attach-internet-gateway --internet-gateway-id igw-xxxxxxxx --vpc-id vpc-xxxxxxxx` | **Gateway Attachment** | Connect internet gateway to VPC |
| `aws ec2 describe-internet-gateways --internet-gateway-ids igw-xxxxxxxx` | **Gateway Information** | Get internet gateway details |
| `aws ec2 detach-internet-gateway --internet-gateway-id igw-xxxxxxxx --vpc-id vpc-xxxxxxxx` | **Gateway Detachment** | Disconnect gateway from VPC |
| `aws ec2 delete-internet-gateway --internet-gateway-id igw-xxxxxxxx` | **Gateway Cleanup** | Delete internet gateway |

### Route Table Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws ec2 create-route-table --vpc-id vpc-xxxxxxxx` | **Traffic Routing** | Create custom routing table for subnet |
| `aws ec2 create-route --route-table-id rtb-xxxxxxxx --destination-cidr-block 0.0.0.0/0 --gateway-id igw-xxxxxxxx` | **Internet Route** | Add route to internet gateway for all traffic |
| `aws ec2 associate-route-table --subnet-id subnet-xxxxxxxx --route-table-id rtb-xxxxxxxx` | **Route Association** | Connect subnet to specific route table |
| `aws ec2 describe-route-tables --filters "Name=vpc-id,Values=vpc-xxxxxxxx"` | **Route Inventory** | List all route tables in VPC |
| `aws ec2 delete-route-table --route-table-id rtb-xxxxxxxx` | **Route Cleanup** | Delete custom route table |

---

## 🔒 Security Group Commands

### Security Group Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws ec2 create-security-group --group-name demo-sg --description "Demo security group" --vpc-id vpc-xxxxxxxx` | **Firewall Creation** | Create instance-level firewall rules |
| `aws ec2 authorize-security-group-ingress --group-id sg-xxxxxxxx --protocol tcp --port 22 --cidr 203.0.113.5/32` | **Allow Rule** | Add inbound access rule (SSH from specific IP) |
| `aws ec2 describe-security-groups --group-ids sg-xxxxxxxx` | **Rule Inspection** | View all firewall rules for security group |
| `aws ec2 revoke-security-group-ingress --group-id sg-xxxxxxxx --protocol tcp --port 22 --cidr 203.0.113.5/32` | **Rule Removal** | Remove specific inbound rule |
| `aws ec2 delete-security-group --group-id sg-xxxxxxxx` | **Firewall Cleanup** | Delete security group |

---

## 🛡️ Network ACL Commands

### Network ACL Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws ec2 create-network-acl --vpc-id vpc-xxxxxxxx` | **Subnet Firewall** | Create subnet-level firewall (stateless) |
| `aws ec2 create-network-acl-entry --network-acl-id acl-xxxxxxxx --rule-number 100 --protocol tcp --port-range From=22,To=22 --cidr-block 203.0.113.5/32 --rule-action allow` | **Inbound Rule** | Add inbound access rule to network ACL |
| `aws ec2 create-network-acl-entry --network-acl-id acl-xxxxxxxx --rule-number 100 --protocol tcp --port-range From=1024,To=65535 --cidr-block 203.0.113.5/32 --rule-action allow --egress` | **Outbound Rule** | Add outbound rule for return traffic |
| `aws ec2 describe-network-acls --network-acl-ids acl-xxxxxxxx` | **ACL Inspection** | View all rules in network ACL |
| `aws ec2 replace-network-acl-association --association-id aclassoc-xxxxxxxx --network-acl-id acl-xxxxxxxx` | **ACL Association** | Associate network ACL with subnet |
| `aws ec2 delete-network-acl --network-acl-id acl-xxxxxxxx` | **ACL Cleanup** | Delete network ACL |

---

## 💻 EC2 (Elastic Compute Cloud) Commands

### Key Pair Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws ec2 create-key-pair --key-name demo-key` | **SSH Authentication** | Create SSH key pair for secure instance access |
| `aws ec2 describe-key-pairs --key-names demo-key` | **Key Verification** | Verify key pair exists and get details |
| `aws ec2 delete-key-pair --key-name demo-key` | **Key Cleanup** | Delete SSH key pair |

### AMI (Amazon Machine Image) Discovery

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws ec2 describe-images --owners amazon --filters "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" "Name=state,Values=available"` | **Image Discovery** | Find latest Amazon Linux AMI for instance launch |
| `aws ec2 describe-availability-zones` | **Zone Discovery** | List available availability zones in region |

### Instance Management

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws ec2 run-instances --image-id ami-xxxxxxxx --instance-type t2.micro --key-name demo-key --security-group-ids sg-xxxxxxxx --subnet-id subnet-xxxxxxxx --iam-instance-profile Name=ec2-s3-profile` | **Secure Launch** | Launch EC2 instance with all security components |
| `aws ec2 describe-instances --instance-ids i-xxxxxxxx` | **Instance Details** | Get comprehensive information about instance |
| `aws ec2 wait instance-running --instance-ids i-xxxxxxxx` | **Status Monitoring** | Wait for instance to reach running state |
| `aws ec2 terminate-instances --instance-ids i-xxxxxxxx` | **Instance Cleanup** | Terminate and delete instance |

---

## 🗄️ S3 (Simple Storage Service) Commands

### Bucket Operations

| Command | Use Case | Meaning |
|---------|----------|---------|
| `aws s3 ls` | **Permission Testing** | List all S3 buckets (tests S3 read permissions) |
| `aws s3api list-buckets` | **Detailed Bucket Info** | Get detailed information about all buckets |
| `aws s3api get-bucket-location --bucket bucket-name` | **Bucket Details** | Get specific bucket location and configuration |

---

## 🔍 Utility and Information Commands

### General AWS Information

| Command | Use Case | Meaning |
|---------|----------|---------|
| `curl https://checkip.amazonaws.com` | **IP Discovery** | Get your current public IP address for security group rules |
| `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` | **Instance Metadata** | View temporary credentials from within EC2 instance |
| `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name` | **Credential Details** | Get detailed temporary credential information |

### Environment and Debugging

| Command | Use Case | Meaning |
|---------|----------|---------|
| `env | grep -i aws` | **Environment Check** | Check for AWS-related environment variables |
| `ls -la ~/.aws/` | **Credential File Check** | Verify presence of AWS credential files |
| `echo $AWS_ACCESS_KEY_ID` | **Variable Verification** | Check if AWS credentials are set as environment variables |

---

## 📊 Command Organization by Demo

### Demo 1 - Account Security Foundation
- `aws configure`
- `aws sts get-caller-identity`
- `aws iam create-user`
- `aws iam create-login-profile`
- `aws iam attach-user-policy`
- `aws iam create-access-key`

### Demo 2 - IAM Permission Control
- `aws iam create-group`
- `aws iam add-user-to-group`
- `aws iam create-policy`
- `aws iam attach-user-policy`
- `aws s3 ls --profile`
- `aws iam list-users --profile`

### Demo 3 - IAM Roles & Service Authentication
- `aws iam create-role`
- `aws iam attach-role-policy`
- `aws iam create-instance-profile`
- `aws iam add-role-to-instance-profile`
- `aws sts assume-role`

### Demo 4 - VPC Network Architecture
- `aws ec2 create-vpc`
- `aws ec2 create-subnet`
- `aws ec2 create-internet-gateway`
- `aws ec2 attach-internet-gateway`
- `aws ec2 create-route-table`
- `aws ec2 create-route`
- `aws ec2 associate-route-table`

### Demo 5 - Network Firewall Defense
- `aws ec2 create-security-group`
- `aws ec2 authorize-security-group-ingress`
- `aws ec2 create-network-acl`
- `aws ec2 create-network-acl-entry`
- `aws ec2 describe-security-groups`

### Demo 6 - Secure EC2 Launch
- `aws ec2 create-key-pair`
- `aws ec2 describe-images`
- `aws ec2 run-instances`
- `aws ec2 wait instance-running`
- `aws ec2 describe-instances`

### Demo 7 - Complete Validation
- `aws s3 ls` (from EC2)
- `aws ec2 describe-instances` (should fail)
- `aws iam list-users` (should fail)
- `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`

---

## 🧹 Cleanup Commands Summary

For complete resource cleanup after demos:

| Resource Type | Cleanup Commands |
|---------------|------------------|
| **EC2 Instances** | `aws ec2 terminate-instances` |
| **Key Pairs** | `aws ec2 delete-key-pair` |
| **Security Groups** | `aws ec2 delete-security-group` |
| **Network ACLs** | `aws ec2 delete-network-acl` |
| **Subnets** | `aws ec2 delete-subnet` |
| **Route Tables** | `aws ec2 delete-route-table` |
| **Internet Gateways** | `aws ec2 detach-internet-gateway`, `aws ec2 delete-internet-gateway` |
| **VPCs** | `aws ec2 delete-vpc` |
| **Instance Profiles** | `aws iam remove-role-from-instance-profile`, `aws iam delete-instance-profile` |
| **IAM Roles** | `aws iam detach-role-policy`, `aws iam delete-role` |
| **IAM Policies** | `aws iam detach-user-policy`, `aws iam delete-policy` |
| **IAM Users** | `aws iam delete-access-key`, `aws iam delete-login-profile`, `aws iam delete-user` |
| **IAM Groups** | `aws iam remove-user-from-group`, `aws iam detach-group-policy`, `aws iam delete-group` |

---

## 📝 Notes

- **Replace placeholders** like `vpc-xxxxxxxx`, `sg-xxxxxxxx`, `ACCOUNT-ID` with actual values
- **Commands are region-specific** - ensure consistent region usage throughout demos
- **Some commands require prerequisites** - follow demo sequence for dependencies
- **Free tier eligible** - All commands use resources within AWS free tier limits
- **Security best practice** - Always clean up resources after demonstrations to avoid charges

This reference provides comprehensive coverage of all CLI commands used across the AWS Security Architecture demo series, organized for easy lookup and understanding.