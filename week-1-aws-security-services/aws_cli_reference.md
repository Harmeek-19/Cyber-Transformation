# AWS Security Architecture Demos - CLI Commands Used

## 📋 Commands Used in Live Demonstrations

This document contains **only** the CLI commands actually used in the 7 AWS Security Architecture demos, organized by demonstration sequence.

---

## 🔒 Instance Metadata Service (IMDS) Commands

### IMDSv1 vs IMDSv2 Security

Modern EC2 instances often require **IMDSv2** (Instance Metadata Service version 2) for enhanced security. This requires token-based authentication instead of simple GET requests.

| Command Type | IMDSv1 (Legacy) | IMDSv2 (Secure - Required) |
|--------------|-----------------|----------------------------|
| **Token Generation** | Not required | `TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)` |
| **Role Name Retrieval** | `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` | `curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/` |
| **Credential Retrieval** | `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]` | `curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]` |

### Why IMDSv2 is Required:

**Security Benefits:**
- **SSRF Attack Prevention:** Two-step process prevents Server-Side Request Forgery attacks
- **Session Management:** Tokens expire (configurable 1 second to 6 hours)  
- **Intent Verification:** PUT request + header proves intentional access
- **Defense in Depth:** Additional security layer beyond IAM roles

**Instance Configuration:**
- **`"HttpTokens": "required"`** - Only IMDSv2 allowed (modern default)
- **`"HttpTokens": "optional"`** - Both IMDSv1 and IMDSv2 allowed (legacy)
- **`"HttpTokens": "disabled"`** - No metadata access allowed

### Demo Context:
> *"Modern AWS instances use IMDSv2 by default for security. The token-based authentication prevents malicious applications from accidentally accessing instance credentials through common web vulnerabilities."*

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
| `TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)` | Get IMDSv2 authentication token | Required for secure metadata access on modern instances |
| `curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/` | List available IAM role credentials | Shows role name attached to instance |
| `curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3` | Show instance credentials | Display temporary, auto-rotating credentials |

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
| `TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)` | Get IMDSv2 authentication token | Required for secure metadata access on modern instances |
| `curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/` | List available IAM role credentials | Shows role name attached to instance |
| `curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3` | Show instance credentials | Display temporary, auto-rotating credentials |
| `curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3 \| grep Expiration` | Show credential expiration | Display when credentials expire (6-hour rotation) |
| `ls -la ~/.aws/` | Check for credential files | Should show no files - proves no hardcoded credentials |
| `env \| grep -i aws` | Check environment variables | Should show no AWS variables - proves no hardcoded credentials |

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
- `TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)` - Get secure metadata token
- `curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/` - Show automatic credentials

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
- IMDSv2 token authentication working on modern instances

### **IMDSv2 Security Note:**
Modern EC2 instances require **IMDSv2** (Instance Metadata Service version 2) for enhanced security. Always use token-based authentication:

```bash
# Required pattern for modern instances
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s)
curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
```

**Security Benefits:**
- Prevents SSRF (Server-Side Request Forgery) attacks
- Session-based authentication with token expiration
- Ensures only legitimate applications access credentials
- Required on modern AWS instances for compliance


C:\Users\E114963\Downloads>aws ec2 describe-instances --instance-ids i-0642aa798338cce4a
{
    "Reservations": [
        {
            "ReservationId": "r-0024bfc0bad430b18",
            "OwnerId": "733366527973",
            "Groups": [],
            "Instances": [
                {
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/xvda",
                            "Ebs": {
                                "AttachTime": "2025-08-07T09:44:36+00:00",
                                "DeleteOnTermination": true,
                                "Status": "attached",
                                "VolumeId": "vol-010f38b4ce929d71b"
                            }
                        }
                    ],
                    "ClientToken": "6906317a-6cf5-4272-b67a-383945e3cf33",
                    "EbsOptimized": true,
                    "EnaSupport": true,
                    "Hypervisor": "xen",
                    "IamInstanceProfile": {
                        "Arn": "arn:aws:iam::733366527973:instance-profile/iamroletestingec2s3",
                        "Id": "AIPA2VQANE7S342GWJYE2"
                    },
                    "NetworkInterfaces": [
                        {
                            "Association": {
                                "IpOwnerId": "amazon",
                                "PublicDnsName": "ec2-44-198-164-135.compute-1.amazonaws.com",
                                "PublicIp": "44.198.164.135"
                            },
                            "Attachment": {
                                "AttachTime": "2025-08-07T09:44:35+00:00",
                                "AttachmentId": "eni-attach-088e80e5470dd1ce1",
                                "DeleteOnTermination": true,
                                "DeviceIndex": 0,
                                "Status": "attached",
                                "NetworkCardIndex": 0
                            },
                            "Description": "",
                            "Groups": [
                                {
                                    "GroupId": "sg-0b6120249b37d52c6",
                                    "GroupName": "test-sg"
                                }
                            ],
                            "Ipv6Addresses": [],
                            "MacAddress": "02:12:49:6b:0e:49",
                            "NetworkInterfaceId": "eni-0541cd37dbeeb1b60",
                            "OwnerId": "733366527973",
                            "PrivateDnsName": "ip-10-0-1-5.ec2.internal",
                            "PrivateIpAddress": "10.0.1.5",
                            "PrivateIpAddresses": [
                                {
                                    "Association": {
                                        "IpOwnerId": "amazon",
                                        "PublicDnsName": "ec2-44-198-164-135.compute-1.amazonaws.com",
                                        "PublicIp": "44.198.164.135"
                                    },
                                    "Primary": true,
                                    "PrivateDnsName": "ip-10-0-1-5.ec2.internal",
                                    "PrivateIpAddress": "10.0.1.5"
                                }
                            ],
                            "SourceDestCheck": true,
                            "Status": "in-use",
                            "SubnetId": "subnet-05903635218ff000c",
                            "VpcId": "vpc-045ada19755bf2191",
                            "InterfaceType": "interface",
                            "Operator": {
                                "Managed": false
                            }
                        }
                    ],
                    "RootDeviceName": "/dev/xvda",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-0b6120249b37d52c6",
                            "GroupName": "test-sg"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": "test-web-server"
                        }
                    ],
                    "VirtualizationType": "hvm",
                    "CpuOptions": {
                        "CoreCount": 1,
                        "ThreadsPerCore": 2
                    },
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "open"
                    },
                    "HibernationOptions": {
                        "Configured": false
                    },
                    "MetadataOptions": {
                        "State": "applied",
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 2,
                        "HttpEndpoint": "enabled",
                        "HttpProtocolIpv6": "disabled",
                        "InstanceMetadataTags": "disabled"
                    },
                    "EnclaveOptions": {
                        "Enabled": false
                    },
                    "BootMode": "uefi-preferred",
                    "PlatformDetails": "Linux/UNIX",
                    "UsageOperation": "RunInstances",
                    "UsageOperationUpdateTime": "2025-08-07T09:44:35+00:00",
                    "PrivateDnsNameOptions": {
                        "HostnameType": "ip-name",
                        "EnableResourceNameDnsARecord": false,
                        "EnableResourceNameDnsAAAARecord": false                    },
                    "MaintenanceOptions": {
                        "AutoRecovery": "default",
                        "RebootMigration": "default"
                    },
                    "CurrentInstanceBootMode": "uefi",
                    "NetworkPerformanceOptions": {
                        "BandwidthWeighting": "default"
                    },
                    "Operator": {
                        "Managed": false
                    },
                    "InstanceId": "i-0642aa798338cce4a",
                    "ImageId": "ami-084a7d336e816906b",
                    "State": {
                        "Code": 16,
                        "Name": "running"
                    },
                    "PrivateDnsName": "ip-10-0-1-5.ec2.internal",
                    "PublicDnsName": "ec2-44-198-164-135.compute-1.amazonaws.com",
                    "StateTransitionReason": "",
                    "KeyName": "myfirstkey",
                    "AmiLaunchIndex": 0,
                    "ProductCodes": [],
                    "InstanceType": "t3.micro",
                    "LaunchTime": "2025-08-07T09:44:35+00:00",
                    "Placement": {
                        "GroupName": "",
                        "Tenancy": "default",
                        "AvailabilityZone": "us-east-1a"
                    },
                    "Monitoring": {
                        "State": "disabled"
                    },
                    "SubnetId": "subnet-05903635218ff000c",
                    "VpcId": "vpc-045ada19755bf2191",
                    "PrivateIpAddress": "10.0.1.5",
                    "PublicIpAddress": "44.198.164.135"
                }
            ]
        }
    ]
}


C:\Users\E114963\Downloads>aws ec2 describe-security-groups --group-ids sg-0b6120249b37d52c6
{
    "SecurityGroups": [
        {
            "GroupId": "sg-0b6120249b37d52c6",
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "UserIdGroupPairs": [],
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": []
                }
            ],
            "VpcId": "vpc-045ada19755bf2191",
            "SecurityGroupArn": "arn:aws:ec2:us-east-1:733366527973:security-group/sg-0b6120249b37d52c6",
            "OwnerId": "733366527973",
            "GroupName": "test-sg",
            "Description": "test-sg",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "UserIdGroupPairs": [],
                    "IpRanges": [
                        {
                            "CidrIp": "130.41.61.150/32"
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": []
                }
            ]
        }
    ]
}


C:\Users\E114963\Downloads>aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-045ada19755bf2191"
{
    "Subnets": [
        {
            "AvailabilityZoneId": "use1-az1",
            "MapCustomerOwnedIpOnLaunch": false,
            "OwnerId": "733366527973",
            "AssignIpv6AddressOnCreation": false,
            "Ipv6CidrBlockAssociationSet": [],
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "private-subnet"
                }
            ],
            "SubnetArn": "arn:aws:ec2:us-east-1:733366527973:subnet/subnet-0f582a497ad8233f0",
            "EnableDns64": false,
            "Ipv6Native": false,
            "PrivateDnsNameOptionsOnLaunch": {
                "HostnameType": "ip-name",
                "EnableResourceNameDnsARecord": false,
                "EnableResourceNameDnsAAAARecord": false
            },
            "BlockPublicAccessStates": {
                "InternetGatewayBlockMode": "off"
            },
            "SubnetId": "subnet-0f582a497ad8233f0",
            "State": "available",
            "VpcId": "vpc-045ada19755bf2191",
            "CidrBlock": "10.0.2.0/24",
            "AvailableIpAddressCount": 251,
            "AvailabilityZone": "us-east-1a",
            "DefaultForAz": false,
            "MapPublicIpOnLaunch": false
        },
        {
            "AvailabilityZoneId": "use1-az1",
            "MapCustomerOwnedIpOnLaunch": false,
            "OwnerId": "733366527973",
            "AssignIpv6AddressOnCreation": false,
            "Ipv6CidrBlockAssociationSet": [],
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "public-subnet"
                }
            ],
            "SubnetArn": "arn:aws:ec2:us-east-1:733366527973:subnet/subnet-05903635218ff000c",
            "EnableDns64": false,
            "Ipv6Native": false,
            "PrivateDnsNameOptionsOnLaunch": {
                "HostnameType": "ip-name",
                "EnableResourceNameDnsARecord": false,
                "EnableResourceNameDnsAAAARecord": false
            },
            "BlockPublicAccessStates": {
                "InternetGatewayBlockMode": "off"
            },
            "SubnetId": "subnet-05903635218ff000c",
            "State": "available",
            "VpcId": "vpc-045ada19755bf2191",
            "CidrBlock": "10.0.1.0/24",
            "AvailableIpAddressCount": 250,
            "AvailabilityZone": "us-east-1a",
            "DefaultForAz": false,
            "MapPublicIpOnLaunch": true
        }
    ]
}


C:\Users\E114963\Downloads>aws ec2 describe-route-tables --filters "Name=vpc-id,Values=vpc-045ada19755bf2191
{
    "RouteTables": [
        {
            "Associations": [
                {
                    "Main": false,
                    "RouteTableAssociationId": "rtbassoc-0f2df181d1c6ac075",
                    "RouteTableId": "rtb-0e4c0a171e47f976d",
                    "SubnetId": "subnet-05903635218ff000c",
                    "AssociationState": {
                        "State": "associated"
                    }
                }
            ],
            "PropagatingVgws": [],
            "RouteTableId": "rtb-0e4c0a171e47f976d",
            "Routes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "GatewayId": "local",
                    "Origin": "CreateRouteTable",
                    "State": "active"
                },
                {
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "igw-060444d92ba7c165d",
                    "Origin": "CreateRoute",
                    "State": "active"
                }
            ],
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "public-rt"
                }
            ],
            "VpcId": "vpc-045ada19755bf2191",
            "OwnerId": "733366527973"
        },
        {
            "Associations": [
                {
                    "Main": false,
                    "RouteTableAssociationId": "rtbassoc-0b1916598f15b4eb5",
                    "RouteTableId": "rtb-075617bf1d29ca532",
                    "SubnetId": "subnet-0f582a497ad8233f0",
                    "AssociationState": {
                        "State": "associated"
                    }
                }
            ],
            "PropagatingVgws": [],
            "RouteTableId": "rtb-075617bf1d29ca532",
            "Routes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "GatewayId": "local",
                    "Origin": "CreateRouteTable",
                    "State": "active"
                }
            ],
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "private-rt"
                }
            ],
            "VpcId": "vpc-045ada19755bf2191",
            "OwnerId": "733366527973"
        },
        {
            "Associations": [
                {
                    "Main": true,
                    "RouteTableAssociationId": "rtbassoc-07641ac0906404cec",
                    "RouteTableId": "rtb-02788d2f6f283a677",
                    "AssociationState": {
                        "State": "associated"
                    }
                }
            ],
            "PropagatingVgws": [],
            "RouteTableId": "rtb-02788d2f6f283a677",
            "Routes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "GatewayId": "local",
                    "Origin": "CreateRouteTable",
                    "State": "active"
                }
            ],
            "Tags": [],
            "VpcId": "vpc-045ada19755bf2191",
            "OwnerId": "733366527973"
        }
    ]
}


C:\Users\E114963\Downloads>aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=vpc-045ada19755bf2191"
{
    "InternetGateways": [
        {
            "Attachments": [
                {
                    "State": "available",
                    "VpcId": "vpc-045ada19755bf2191"
                }
            ],
            "InternetGatewayId": "igw-060444d92ba7c165d",
            "OwnerId": "733366527973",
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "test-igw"
                }
            ]
        }
    ]
}


C:\Users\E114963\Downloads>aws ec2 describe-network-acls --network-acl-ids acl-0f664344526221329
{
    "NetworkAcls": [
        {
            "Associations": [
                {
                    "NetworkAclAssociationId": "aclassoc-03ce4698f2000ea5e",
                    "NetworkAclId": "acl-0f664344526221329",
                    "SubnetId": "subnet-05903635218ff000c"
                },
                {
                    "NetworkAclAssociationId": "aclassoc-0a290df2a294cffce",
                    "NetworkAclId": "acl-0f664344526221329",
                    "SubnetId": "subnet-0f582a497ad8233f0"
                }
            ],
            "Entries": [
                {
                    "CidrBlock": "130.41.61.150/32",
                    "Egress": true,
                    "PortRange": {
                        "From": 1024,
                        "To": 65535
                    },
                    "Protocol": "6",
                    "RuleAction": "allow",
                    "RuleNumber": 100
                },
                {
                    "CidrBlock": "0.0.0.0/0",
                    "Egress": true,
                    "PortRange": {
                        "From": 80,
                        "To": 80
                    },
                    "Protocol": "6",
                    "RuleAction": "allow",
                    "RuleNumber": 200
                },
                {
                    "CidrBlock": "0.0.0.0/0",
                    "Egress": true,
                    "PortRange": {
                        "From": 443,
                        "To": 443
                    },
                    "Protocol": "6",
                    "RuleAction": "allow",
                    "RuleNumber": 300
                },
                {
                    "CidrBlock": "0.0.0.0/0",
                    "Egress": true,
                    "Protocol": "-1",
                    "RuleAction": "deny",
                    "RuleNumber": 32767
                },
                {
                    "CidrBlock": "130.41.61.150/32",
                    "Egress": false,
                    "PortRange": {
                        "From": 22,
                        "To": 22
                    },
                    "Protocol": "6",
                    "RuleAction": "allow",
                    "RuleNumber": 100
                },
                {
                    "CidrBlock": "0.0.0.0/0",
                    "Egress": false,
                    "Protocol": "-1",
                    "RuleAction": "deny",
                    "RuleNumber": 32767
                }
            ],
            "IsDefault": false,
            "NetworkAclId": "acl-0f664344526221329",
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "test-nacl"
                }
            ],
            "VpcId": "vpc-045ada19755bf2191",
            "OwnerId": "733366527973"
        }
    ]
}
