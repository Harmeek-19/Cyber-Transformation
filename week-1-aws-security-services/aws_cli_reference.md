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

C:\Users\E114963\Downloads>ssh -i myfirstkey.pem ec2-user@34.207.250.126
The authenticity of host '34.207.250.126 (34.207.250.126)' can't be established.
ED25519 key fingerprint is SHA256:G6Uk2IHWbbODVhA7SBgBpzJJaj+WuZvTZizFl6gvfZg.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '34.207.250.126' (ED25519) to the list of known hosts.
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
[ec2-user@ip-172-31-46-189 ~]$ aws s3 ls
2025-07-29 09:59:26 config-bucket-733366527973
2025-07-27 08:40:38 elasticbeanstalk-ap-south-1-733366527973
2025-08-01 08:34:09 my-test-bucket3231342
[ec2-user@ip-172-31-46-189 ~]$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroletestingec2s3
[ec2-user@ip-172-31-46-189 ~]$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroletestingec2s3
[ec2-user@ip-172-31-46-189 ~]$ exit
logout
Connection to 34.207.250.126 closed.

C:\Users\E114963\Downloads>INSTANCE_ID=i-06e179fe55853e04d
'INSTANCE_ID' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\E114963\Downloads>aws ec2 describe-instances
{
    "Reservations": [
        {
            "ReservationId": "r-08cd27316695ffbb9",
            "OwnerId": "733366527973",
            "Groups": [],
            "Instances": [
                {
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/xvda",
                            "Ebs": {
                                "AttachTime": "2025-08-07T05:44:33+00:00",
                                "DeleteOnTermination": true,
                                "Status": "attached",
                                "VolumeId": "vol-0d788830764b98935"
                            }
                        }
                    ],
                    "ClientToken": "7f5a1d65-b08e-4ace-8d8c-be2d7be443d3",
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
                                "PublicDnsName": "ec2-34-207-250-126.compute-1.amazonaws.com",
                                "PublicIp": "34.207.250.126"
                            },
                            "Attachment": {
                                "AttachTime": "2025-08-07T05:44:32+00:00",
                                "AttachmentId": "eni-attach-0a0a2331cca53a25f",
                                "DeleteOnTermination": true,
                                "DeviceIndex": 0,
                                "Status": "attached",
                                "NetworkCardIndex": 0
                            },
                            "Description": "",
                            "Groups": [
                                {
                                    "GroupId": "sg-0692fecf78b584368",
                                    "GroupName": "launch-wizard-3"
                                }
                            ],
                            "Ipv6Addresses": [],
                            "MacAddress": "0e:5d:7b:5b:ca:35",
                            "NetworkInterfaceId": "eni-0a5542c24fc07ddfe",
                            "OwnerId": "733366527973",
                            "PrivateDnsName": "ip-172-31-46-189.ec2.internal",
                            "PrivateIpAddress": "172.31.46.189",                            "PrivateIpAddresses": [
                                {
                                    "Association": {
                                        "IpOwnerId": "amazon",
                                        "PublicDnsName": "ec2-34-207-250-126.compute-1.amazonaws.com",
                                        "PublicIp": "34.207.250.126"
                                    },
                                    "Primary": true,
                                    "PrivateDnsName": "ip-172-31-46-189.ec2.internal",
                                    "PrivateIpAddress": "172.31.46.189"
                                }
                            ],
                            "SourceDestCheck": true,
                            "Status": "in-use",
                            "SubnetId": "subnet-0664e729bfdbfd543",
                            "VpcId": "vpc-0e58e3030aefcad46",
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
                            "GroupId": "sg-0692fecf78b584368",
                            "GroupName": "launch-wizard-3"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": "test-server-ec2-s3"
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
                    "UsageOperationUpdateTime": "2025-08-07T05:44:32+00:00",
                    "PrivateDnsNameOptions": {
                        "HostnameType": "ip-name",
                        "EnableResourceNameDnsARecord": true,
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
                    "InstanceId": "i-06e179fe55853e04d",
                    "ImageId": "ami-084a7d336e816906b",
                    "State": {
                        "Code": 16,
                        "Name": "running"
                    },
                    "PrivateDnsName": "ip-172-31-46-189.ec2.internal",
                    "PublicDnsName": "ec2-34-207-250-126.compute-1.amazonaws.com",
                    "StateTransitionReason": "",
                    "KeyName": "myfirstkey",
                    "AmiLaunchIndex": 0,
                    "ProductCodes": [],
                    "InstanceType": "t3.micro",
                    "LaunchTime": "2025-08-07T05:44:32+00:00",
                    "Placement": {
                        "GroupName": "",
                        "Tenancy": "default",
                        "AvailabilityZone": "us-east-1d"
                    },
                    "Monitoring": {
                        "State": "disabled"
                    },
                    "SubnetId": "subnet-0664e729bfdbfd543",
                    "VpcId": "vpc-0e58e3030aefcad46",
                    "PrivateIpAddress": "172.31.46.189",
                    "PublicIpAddress": "34.207.250.126"
                }
            ]
        },
        {
            "ReservationId": "r-07a1a9d3505dd32e8",
            "OwnerId": "733366527973",
            "Groups": [],
            "Instances": [
                {
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [],
                    "ClientToken": "dadc97c4-880f-41a1-be16-012e45ad3b9f",
                    "EbsOptimized": true,
                    "EnaSupport": true,
                    "Hypervisor": "xen",
                    "NetworkInterfaces": [],
                    "RootDeviceName": "/dev/xvda",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [],
                    "StateReason": {
                        "Code": "Client.UserInitiatedShutdown",
                        "Message": "Client.UserInitiatedShutdown: User initiated shutdown"
                    },
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": "test-server-ec2-s3"
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
                        "State": "pending",
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
                    "UsageOperationUpdateTime": "2025-08-07T05:12:03+00:00",
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
                    "InstanceId": "i-0a3f7cb85bd553846",
                    "ImageId": "ami-084a7d336e816906b",
                    "State": {
                        "Code": 48,
                        "Name": "terminated"
                    },
                    "PrivateDnsName": "",
                    "PublicDnsName": "",
                    "StateTransitionReason": "User initiated (2025-08-07 05:42:55 GMT)",
                    "KeyName": "myfirstkey",
                    "AmiLaunchIndex": 0,
                    "ProductCodes": [],
                    "InstanceType": "t3.micro",
                    "LaunchTime": "2025-08-07T05:12:03+00:00",
                    "Placement": {
                        "GroupName": "",
                        "Tenancy": "default",
                        "AvailabilityZone": "us-east-1d"
                    },
                    "Monitoring": {
                        "State": "disabled"
                    }
                }
            ]
        }
    ]
}


C:\Users\E114963\Downloads>aws ec2 describe-instances --instance-ids $i-06e179fe55853e04d --query 'Reservations[0].Instances[0].IamInstanceProfile'

An error occurred (InvalidInstanceID.Malformed) when calling the DescribeInstances operation: Invalid id: "$i-06e179fe55853e04d"

C:\Users\E114963\Downloads>aws ec2 describe-instances --instance-ids i-06e179fe55853e04d --query 'Reservations[0].Instances[0].IamInstanceProfile'
"Reservations[0].Instances[0].IamInstanceProfile"


C:\Users\E114963\Downloads>
