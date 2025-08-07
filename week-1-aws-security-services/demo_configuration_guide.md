# AWS Security Architecture - Complete Demo Configuration Guide

## **🎯 Step-by-Step Demo Instructions (Console + CLI Options)**

---

## **Demo 1: Account Security Foundation**

### **Pre-Demo Setup:**
- Have AWS account ready (fresh account preferred)
- Install AWS CLI on local machine
- Have phone with authenticator app ready

### **🖥️ Console Method:**

#### **Step 1: Root Account MFA Setup**
1. **Login to AWS Console** as root user
2. **Navigate to IAM Dashboard**
   - Search "IAM" in services or click "Services" → "Security, Identity & Compliance" → "IAM"
   - Look for orange "Security recommendations" section
   - Click "Add MFA for root user"

3. **Setup Virtual MFA Device**
   - Click "Add MFA" button
   - Choose "Virtual MFA device" radio button
   - Click "Continue"
   - Open authenticator app (Google Authenticator/Authy/Microsoft Authenticator)
   - Scan QR code with phone camera
   - Enter two consecutive MFA codes from app (wait for refresh between codes)
   - Click "Assign MFA"
   - ✅ Confirmation: "You have successfully assigned virtual MFA"

#### **Step 2: Create IAM Administrator User**
1. **Go to IAM → Users**
   - Click "Users" in left navigation panel
   - Click "Create user" button

2. **User Details**
   - Username: `admin-user`
   - Check ☑️ "Provide user access to AWS Management Console"
   - Select ⚪ "I want to create an IAM user"
   - Console password: Choose "Custom password"
   - Enter strong password: `AdminPass123!@#`
   - Uncheck ☐ "Users must create a new password at next sign-in"
   - Click "Next"

3. **Set Permissions**
   - Select ⚪ "Attach policies directly"
   - Search for "AdministratorAccess"
   - Check ☑️ "AdministratorAccess" policy
   - Click "Next"
   - Review and click "Create user"

4. **Create Access Keys**
   - Click on the created user "admin-user"
   - Click "Security credentials" tab
   - Scroll to "Access keys" section
   - Click "Create access key"
   - Choose ⚪ "Command Line Interface (CLI)"
   - Check ☑️ confirmation box "I understand the above recommendation"
   - Click "Next"
   - Description tag: "Admin CLI Access"
   - Click "Create access key"
   - ⚠️ **CRITICAL:** Click "Download .csv file" immediately
   - Click "Done"

#### **Step 3: Configure AWS CLI**
1. **Open Terminal/Command Prompt**
2. **Install AWS CLI** (if not installed):
   ```bash
   # Windows: Download from AWS website
   # macOS: brew install awscli
   # Linux: pip install awscli
   ```

3. **Configure CLI**:
   ```bash
   aws configure
   # AWS Access Key ID: [from downloaded CSV file]
   # AWS Secret Access Key: [from downloaded CSV file]
   # Default region name: us-east-1
   # Default output format: json
   ```

### **💻 CLI Method:**

#### **Step 1: Create IAM Administrator User**
```bash
# Create user
aws iam create-user --user-name admin-user

# Create login profile
aws iam create-login-profile --user-name admin-user --password AdminPass123!@# --no-password-reset-required

# Attach administrator policy
aws iam attach-user-policy --user-name admin-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create access keys
aws iam create-access-key --user-name admin-user
# Note: Save the AccessKeyId and SecretAccessKey from output
```

#### **Step 2: Configure CLI with New User**
```bash
aws configure
# Enter the access keys from previous command output
```

### **Verification (Both Methods):**
```bash
# Test CLI configuration
aws sts get-caller-identity
# Expected: Should show admin-user ARN, not root

# Verify region and configuration
aws configure list
```

### **Expected Results:**
✅ Root account has MFA enabled (Console shows green checkmark)  
✅ Admin user created with AdministratorAccess policy  
✅ AWS CLI configured and working  
✅ Identity verification shows admin user (not root)

---

## **Demo 2: IAM Permission Control**

### **🖥️ Console Method:**

#### **Step 1: Create Test User (No Permissions)**
1. **Go to IAM → Users → Create user**
   - Username: `test-user`
   - Check ☑️ "Provide user access to AWS Management Console"
   - Password: `TestPass123!`
   - Uncheck ☐ "Users must create a new password at next sign-in"
   - Click "Next"

2. **Skip Permissions (Important!)**
   - Don't attach any policies or groups
   - Click "Next" → "Create user"

3. **Create Access Keys**
   - Click on "test-user"
   - "Security credentials" tab
   - "Create access key" → "CLI"
   - Download CSV file

#### **Step 2: Test No Permissions**
1. **Open Incognito/Private Browser Window**
2. **Login as test-user**
   - Go to AWS Console sign-in
   - Account ID: [Your account ID - found in top right of console]
   - Username: `test-user`
   - Password: `TestPass123!`
   - Try to access S3: Search "S3" → Click
   - ❌ Expected: "Access Denied" error

3. **Test via CLI**:
   ```bash
   # Configure test-user profile
   aws configure --profile test-user
   # Enter test-user access keys from CSV
   
   # Try S3 access (should fail)
   aws s3 ls --profile test-user
   # Expected: AccessDenied error
   ```

#### **Step 3: Create IAM Read-Only Group**
1. **Go to IAM → User groups → Create group**
   - Group name: `iamreadonly`
   - Search and select "IAMReadOnlyAccess" policy
   - Click "Create group"

2. **Add User to Group**
   - Click on "iamreadonly" group
   - "Users" tab → "Add users"
   - Select ☑️ "test-user"
   - Click "Add users"

#### **Step 4: Test Group Permissions**
1. **In test-user browser session:**
   - Refresh page and try IAM service
   - Navigate to IAM → Users
   - ✅ Should now work - can see user list

2. **Via CLI:**
   ```bash
   # Test IAM access (should work now)
   aws iam list-users --profile test-user
   # Expected: Success, shows user list
   
   # Try S3 again (should still fail)
   aws s3 ls --profile test-user
   # Expected: Still "Access Denied"
   ```

#### **Step 5: Create Custom S3 Policy**
1. **Go to IAM → Policies → Create policy**
2. **Visual Editor:**
   - Service: S3
   - Actions: 
     - List: ☑️ "ListAllMyBuckets", ☑️ "ListBucket"
     - Read: ☑️ "GetObject", ☑️ "GetBucketLocation"
   - Resources: All resources (*)
   - Click "Next"

3. **Policy Details:**
   - Name: `iampolicytests3full`
   - Description: "S3 read access for testing"
   - Click "Create policy"

4. **Attach Policy to User:**
   - Go to IAM → Users → test-user
   - "Permissions" tab → "Add permissions" → "Attach policies directly"
   - Search and select "iampolicytests3full"
   - Click "Add permissions"

#### **Step 6: Final Permission Test**
1. **In test-user browser:**
   - Navigate to S3 service
   - ✅ Should now work - can see S3 buckets

2. **Via CLI:**
   ```bash
   # Test S3 access (should work now)
   aws s3 ls --profile test-user
   # Expected: Success, shows S3 buckets
   
   # Test EC2 access (should fail)
   aws ec2 describe-instances --profile test-user
   # Expected: "Access Denied"
   ```

### **💻 CLI Method:**

```bash
# Create user
aws iam create-user --user-name test-user

# Create login profile
aws iam create-login-profile --user-name test-user --password TestPass123! --no-password-reset-required

# Create access keys
aws iam create-access-key --user-name test-user

# Create group
aws iam create-group --group-name iamreadonly

# Attach policy to group
aws iam attach-group-policy --group-name iamreadonly --policy-arn arn:aws:iam::aws:policy/IAMReadOnlyAccess

# Add user to group
aws iam add-user-to-group --group-name iamreadonly --user-name test-user

# Create custom S3 policy
cat > s3-read-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": "*"
        }
    ]
}
EOF

# Create and attach policy
aws iam create-policy --policy-name iampolicytests3full --policy-document file://s3-read-policy.json
aws iam attach-user-policy --user-name test-user --policy-arn arn:aws:iam::[ACCOUNT-ID]:policy/iampolicytests3full
```

### **Expected Results:**
✅ User starts with no permissions (access denied everywhere)  
✅ Group membership grants IAM read access  
✅ Custom policy grants S3 access  
✅ User has exactly IAM read + S3 access (least privilege working)

---

## **Demo 3: IAM Roles & Service Authentication**

### **🖥️ Console Method:**

#### **Part A: User Role Assumption**

#### **Step 1: Create Second Test User**
1. **IAM → Users → Create user**
   - Username: `neil2`
   - No console access needed
   - No permissions/groups
   - Create access keys

#### **Step 2: Create Role for S3 Access**
1. **IAM → Roles → Create role**
2. **Select trusted entity:**
   - Choose "AWS account"
   - Select "This account ([Your Account ID])"
   - Click "Next"

3. **Add permissions:**
   - Search and select "AmazonS3ReadOnlyAccess"
   - Click "Next"

4. **Role details:**
   - Role name: `iamroletests3`
   - Description: "S3 read access role for testing"
   - Click "Create role"

5. **Configure Trust Policy:**
   - Click on created role "iamroletests3"
   - "Trust relationships" tab → "Edit trust policy"
   - Replace the policy with:
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Principal": {
                   "AWS": "arn:aws:iam::[ACCOUNT-ID]:user/neil2"
               },
               "Action": "sts:AssumeRole"
           }
       ]
   }
   ```
   - Click "Update policy"

#### **Step 3: Test Role Assumption**
1. **Via CLI:**
   ```bash
   # Configure neil2 profile
   aws configure --profile neil2
   # Enter neil2 access keys
   
   # Try S3 without role (should fail)
   aws s3 ls --profile neil2
   # Expected: "Access Denied"
   
   # Assume role
   aws sts assume-role --role-arn arn:aws:iam::[ACCOUNT-ID]:role/iamroletests3 --role-session-name test-session --profile neil2
   
   # Export temporary credentials (from output above)
   export AWS_ACCESS_KEY_ID=ASIA...
   export AWS_SECRET_ACCESS_KEY=...
   export AWS_SESSION_TOKEN=...
   
   # Test S3 with role (should work)
   aws s3 ls
   # Expected: Success!
   ```

#### **Part B: EC2 Service Role**

#### **Step 4: Create EC2 Service Role**
1. **IAM → Roles → Create role**
2. **Select trusted entity:**
   - Choose "AWS service"
   - Select "EC2"
   - Click "Next"

3. **Add permissions:**
   - Search and select "AmazonS3ReadOnlyAccess"
   - Click "Next"

4. **Role details:**
   - Role name: `iamroleec2s3`
   - Description: "EC2 service role with S3 read access"
   - Click "Create role"

### **💻 CLI Method:**

```bash
# Create user neil2
aws iam create-user --user-name neil2
aws iam create-access-key --user-name neil2

# Create trust policy for user assumption
cat > user-trust-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::[ACCOUNT-ID]:user/neil2"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

# Create role
aws iam create-role --role-name iamroletests3 --assume-role-policy-document file://user-trust-policy.json
aws iam attach-role-policy --role-name iamroletests3 --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# Create EC2 service role
cat > ec2-trust-policy.json << 'EOF'
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
EOF

aws iam create-role --role-name iamroleec2s3 --assume-role-policy-document file://ec2-trust-policy.json
aws iam attach-role-policy --role-name iamroleec2s3 --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws iam create-instance-profile --instance-profile-name ec2-s3-profile
aws iam add-role-to-instance-profile --instance-profile-name ec2-s3-profile --role-name iamroleec2s3
```

### **Expected Results:**
✅ User role assumption provides temporary access  
✅ Access is automatically revoked when session expires  
✅ EC2 service role created for instance attachment  
✅ Roles demonstrate proper trust relationships

---

## **Demo 4: VPC Network Architecture**

### **🖥️ Console Method:**

#### **Step 1: Create Custom VPC**
1. **Navigate to VPC Service**
   - Search "VPC" or Services → Networking & Content Delivery → VPC

2. **Create VPC**
   - Click "Create VPC"
   - Select ⚪ "VPC only"
   - Name tag: `demo-vpc`
   - IPv4 CIDR block: `10.0.0.0/16`
   - IPv6 CIDR block: "No IPv6 CIDR block"
   - Tenancy: "Default"
   - Tags: Name = demo-vpc
   - Click "Create VPC"

3. **Enable DNS Hostnames**
   - Select your VPC → Actions → Edit VPC settings
   - Check ☑️ "Enable DNS hostnames"
   - Click "Save changes"

#### **Step 2: Create Subnets**
1. **Create Public Subnet**
   - VPC → Subnets → "Create subnet"
   - VPC ID: Select your demo-vpc
   - Subnet name: `public-subnet`
   - Availability Zone: us-east-1a
   - IPv4 CIDR block: `10.0.1.0/24`
   - Click "Create subnet"

2. **Create Private Subnet**
   - Click "Create subnet" again
   - VPC ID: Select your demo-vpc
   - Subnet name: `private-subnet`
   - Availability Zone: us-east-1a
   - IPv4 CIDR block: `10.0.2.0/24`
   - Click "Create subnet"

3. **Configure Public Subnet**
   - Select public-subnet → Actions → Edit subnet settings
   - Check ☑️ "Enable auto-assign public IPv4 address"
   - Click "Save"

#### **Step 3: Create and Attach Internet Gateway**
1. **Create Internet Gateway**
   - VPC → Internet gateways → "Create internet gateway"
   - Name tag: `demo-igw`
   - Click "Create internet gateway"

2. **Attach to VPC**
   - Select created IGW → Actions → "Attach to VPC"
   - Select your demo-vpc
   - Click "Attach internet gateway"

#### **Step 4: Configure Route Tables**
1. **Create Public Route Table**
   - VPC → Route tables → "Create route table"
   - Name: `public-rt`
   - VPC: Select demo-vpc
   - Click "Create route table"

2. **Add Route to Internet Gateway**
   - Select public-rt → Routes tab → "Edit routes"
   - Click "Add route"
   - Destination: `0.0.0.0/0`
   - Target: Internet Gateway → select demo-igw
   - Click "Save changes"

3. **Associate Public Subnet**
   - Routes tab → "Subnet associations" tab → "Edit subnet associations"
   - Select ☑️ public-subnet
   - Click "Save associations"

### **💻 CLI Method:**

```bash
# Create VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=demo-vpc}]'
export VPC_ID=vpc-xxxxxxxxx

# Enable DNS hostnames
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames

# Get first availability zone
export AZ1=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)

# Create subnets
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 --availability-zone $AZ1 --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=public-subnet}]'
export PUBLIC_SUBNET_ID=subnet-xxxxxxxxx

aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.2.0/24 --availability-zone $AZ1 --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=private-subnet}]'
export PRIVATE_SUBNET_ID=subnet-yyyyyyyyy

# Enable auto-assign public IP
aws ec2 modify-subnet-attribute --subnet-id $PUBLIC_SUBNET_ID --map-public-ip-on-launch

# Create and attach Internet Gateway
aws ec2 create-internet-gateway --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=demo-igw}]'
export IGW_ID=igw-xxxxxxxxx
aws ec2 attach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID

# Create route table and add route
aws ec2 create-route-table --vpc-id $VPC_ID --tag-specifications 'ResourceType=route-table,Tags=[{Key=Name,Value=public-rt}]'
export PUBLIC_RT_ID=rtb-xxxxxxxxx
aws ec2 create-route --route-table-id $PUBLIC_RT_ID --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID
aws ec2 associate-route-table --subnet-id $PUBLIC_SUBNET_ID --route-table-id $PUBLIC_RT_ID
```

### **Expected Results:**
✅ Custom VPC created with 10.0.0.0/16 CIDR  
✅ Public subnet (10.0.1.0/24) with internet access  
✅ Private subnet (10.0.2.0/24) isolated from internet  
✅ DNS resolution enabled  
✅ Route tables properly configured

---

## **Demo 5: Network Firewall Defense**

### **🖥️ Console Method:**

#### **Step 1: Create Security Group**
1. **Navigate to EC2 → Security Groups**
   - Click "Create security group"
   - Security group name: `demo-sg-restrictive`
   - Description: `Restrictive demo security group`
   - VPC: Select demo-vpc
   
2. **Configure Inbound Rules**
   - Inbound rules section → "Add rule"
   - Type: SSH
   - Protocol: TCP
   - Port range: 22
   - Source: "My IP" (automatically detects your IP)
   - Description: "SSH from admin IP only"
   - Click "Create security group"

#### **Step 2: Create Custom NACL**
1. **Navigate to VPC → Network ACLs**
   - Click "Create network ACL"
   - Name: `demo-nacl`
   - VPC: Select demo-vpc
   - Click "Create network ACL"

2. **Configure Inbound Rules**
   - Select demo-nacl → Inbound rules tab → "Edit inbound rules"
   - Add rule:
     - Rule number: 100
     - Type: SSH (22)
     - Source: [Your IP]/32
     - Allow/Deny: Allow
   - Click "Save changes"

3. **Configure Outbound Rules**
   - Outbound rules tab → "Edit outbound rules"
   - Add rules:
     - Rule 100: Custom TCP, Port range: 1024-65535, Destination: [Your IP]/32, Allow
     - Rule 200: HTTP (80), Destination: 0.0.0.0/0, Allow
     - Rule 300: HTTPS (443), Destination: 0.0.0.0/0, Allow
   - Click "Save changes"

4. **Associate with Subnet**
   - Subnet associations tab → "Edit subnet associations"
   - Select ☑️ public-subnet
   - Click "Save changes"

### **💻 CLI Method:**

```bash
# Get your public IP
export MY_IP=$(curl -s https://checkip.amazonaws.com)

# Create security group
aws ec2 create-security-group --group-name demo-sg-restrictive --description "Restrictive demo security group" --vpc-id $VPC_ID
export SG_ID=sg-xxxxxxxxx

# Add SSH rule
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 22 --cidr $MY_IP/32

# Create custom NACL
aws ec2 create-network-acl --vpc-id $VPC_ID --tag-specifications 'ResourceType=network-acl,Tags=[{Key=Name,Value=demo-nacl}]'
export CUSTOM_NACL_ID=acl-xxxxxxxxx

# Add NACL rules
aws ec2 create-network-acl-entry --network-acl-id $CUSTOM_NACL_ID --rule-number 100 --protocol tcp --port-range From=22,To=22 --cidr-block $MY_IP/32 --rule-action allow

aws ec2 create-network-acl-entry --network-acl-id $CUSTOM_NACL_ID --rule-number 100 --protocol tcp --port-range From=1024,To=65535 --cidr-block $MY_IP/32 --rule-action allow --egress

aws ec2 create-network-acl-entry --network-acl-id $CUSTOM_NACL_ID --rule-number 200 --protocol tcp --port-range From=80,To=80 --cidr-block 0.0.0.0/0 --rule-action allow --egress

aws ec2 create-network-acl-entry --network-acl-id $CUSTOM_NACL_ID --rule-number 300 --protocol tcp --port-range From=443,To=443 --cidr-block 0.0.0.0/0 --rule-action allow --egress
```

### **Expected Results:**
✅ Security Group allows SSH from your IP only (stateful)  
✅ NACL provides subnet-level protection (stateless)  
✅ Both layers must allow traffic for connections to work  
✅ Demonstrates defense in depth with multiple firewall layers

---

## **Demo 6: Secure EC2 Launch**

### **🖥️ Console Method:**

#### **Step 1: Create SSH Key Pair**
1. **Navigate to EC2 → Key Pairs**
   - Click "Create key pair"
   - Name: `demo-key`
   - Key pair type: RSA
   - Private key file format: .pem
   - Click "Create key pair"
   - File downloads automatically
   - Save to secure location and set permissions: `chmod 400 demo-key.pem`

#### **Step 2: Launch EC2 Instance**
1. **Navigate to EC2 → Instances**
   - Click "Launch instances"

2. **Name and Tags**
   - Name: `secure-demo-instance`

3. **Application and OS Images (AMI)**
   - Select "Amazon Linux 2023 AMI" (Free tier eligible)

4. **Instance type**
   - Select "t2.micro" (Free tier eligible)

5. **Key pair**
   - Select "demo-key" (created above)

6. **Network settings**
   - Click "Edit"
   - VPC: Select demo-vpc
   - Subnet: Select public-subnet
   - Auto-assign public IP: Enable
   - Firewall (security groups): Select existing security group
   - Select: demo-sg-restrictive

7. **Advanced details**
   - IAM instance profile: ec2-s3-profile
   
8. **Launch instance**
   - Review settings and click "Launch instance"

#### **Step 3: Verify Launch**
1. **Check Instance Status**
   - Go to EC2 → Instances
   - Wait for Status Checks: "2/2 checks passed"
   - Note the Public IPv4 address

### **💻 CLI Method:**

```bash
# Create key pair
aws ec2 create-key-pair --key-name demo-key --query 'KeyMaterial' --output text > demo-key.pem
chmod 400 demo-key.pem

# Get latest Amazon Linux AMI
export AMI_ID=$(aws ec2 describe-images --owners amazon --filters "Name=name,Values=amzn2-ami-hvm-*-x86_64-gp2" "Name=state,Values=available" --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' --output text)

# Launch instance
aws ec2 run-instances \
    --image-id $AMI_ID \
    --instance-type t2.micro \
    --key-name demo-key \
    --security-group-ids $SG_ID \
    --subnet-id $PUBLIC_SUBNET_ID \
    --iam-instance-profile Name=ec2-s3-profile \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=secure-demo-instance}]'

export INSTANCE_ID=i-xxxxxxxxx

# Wait for instance and get public IP
aws ec2 wait instance-running --instance-ids $INSTANCE_ID
export PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
```

### **Expected Results:**
✅ Instance launched in custom VPC (not default)  
✅ Security group restricts access to your IP only  
✅ IAM role attached (no hardcoded credentials needed)  
✅ SSH key-based authentication configured  
✅ Instance in public subnet with internet access

---

## **Demo 7: Complete End-to-End Architecture Validation**

### **🖥️ Console Method:**

#### **Phase 1: Console Verification**
1. **Check VPC Architecture**
   - VPC Dashboard → Your resources
   - Verify: 1 VPC, 2 Subnets, 1 Internet Gateway, 2 Route Tables
   - Click on each resource to verify configuration

2. **Check Security Controls**
   - EC2 → Security Groups → demo-sg-restrictive
   - Verify: Only SSH from your IP allowed
   - VPC → Network ACLs → demo-nacl
   - Verify: Proper inbound/outbound rules

3. **Check IAM Configuration**
   - IAM → Roles → iamroleec2s3
   - Verify: EC2 trusted entity, S3ReadOnlyAccess policy
   - Check trust relationship and permissions

4. **Check EC2 Instance**
   - EC2 → Instances → secure-demo-instance
   - Verify: Running, in demo-vpc, public-subnet, demo-sg-restrictive
   - Note: IAM role attached, public IP assigned

#### **Phase 2: Network Connectivity Test**
```bash
# Test SSH connection
ssh -i demo-key.pem ec2-user@[PUBLIC-IP]

# If connection works, you're now on the EC2 instance
# If it fails, check:
# 1. Security group rules
# 2. NACL rules  
# 3. Route table configuration
# 4. Internet gateway attachment
```

#### **Phase 3: IAM Role Functionality Test**
```bash
# From within EC2 instance:

# Test S3 access (should work)
aws s3 ls
echo "S3 Access Result: $?"

# Test specific S3 operations
aws s3api list-buckets
aws s3api get-bucket-location --bucket [bucket-name] 2>/dev/null || echo "No accessible buckets"

# Test EC2 access (should fail)
aws ec2 describe-instances
echo "Expected: AccessDenied error"

# Test IAM access (should fail)  
aws iam list-users
echo "Expected: AccessDenied error"
```

#### **Phase 4: Security Validation**
```bash
# From within EC2 instance:

# Show temporary credentials (auto-rotating)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3

# Show credential expiration
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/iamroleec2s3 | grep -i expiration

# Verify no hardcoded credentials
ls -la ~/.aws/ 2>/dev/null || echo "No AWS credentials file found (GOOD!)"
env | grep -i aws || echo "No AWS environment variables found (GOOD!)"
```

### **💻 CLI Method:**

#### **Complete Architecture Review**
```bash
# Show complete architecture
echo "=== VPC Architecture ==="
aws ec2 describe-vpcs --vpc-ids $VPC_ID --query 'Vpcs[0].{VpcId:VpcId,CidrBlock:CidrBlock,State:State}'

echo "=== Subnets ==="
aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query 'Subnets[].{SubnetId:SubnetId,CidrBlock:CidrBlock,Type:Tags[?Key==`Name`].Value|[0],AZ:AvailabilityZone}'

echo "=== Internet Gateway ==="
aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$VPC_ID" --query 'InternetGateways[0].{IGWId:InternetGatewayId,State:Attachments[0].State}'

echo "=== Route Tables ==="
aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" --query 'RouteTables[].{RouteTableId:RouteTableId,Routes:Routes[?GatewayId!=`local`]}'

echo "=== Security Groups ==="
aws ec2 describe-security-groups --group-ids $SG_ID --query 'SecurityGroups[0].{GroupId:GroupId,Rules:IpPermissions[0]}'

echo "=== IAM Role ==="
aws iam get-role --role-name iamroleec2s3 --query 'Role.{RoleName:RoleName,CreateDate:CreateDate}'
aws iam list-attached-role-policies --role-name iamroleec2s3

echo "=== Instance Status ==="
aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].{InstanceId:InstanceId,State:State.Name,PublicIp:PublicIpAddress,VPC:VpcId,Subnet:SubnetId,SecurityGroups:SecurityGroups[0].GroupId,IAMRole:IamInstanceProfile.Arn}'
```

#### **Security Test Summary**
```bash
# Summary of all security validations
echo "=== SECURITY VALIDATION SUMMARY ==="
echo "✅ Network Security Tests:"
echo "   - SSH accessible from authorized IP only"
echo "   - All other ports blocked by security group"
echo "   - NACL provides additional subnet-level protection"

echo "✅ Access Control Tests:"  
echo "   - S3 operations: ALLOWED (read-only as designed)"
echo "   - EC2 operations: DENIED (not in role permissions)"
echo "   - IAM operations: DENIED (not in role permissions)"

echo "✅ Authentication Tests:"
echo "   - SSH key-based authentication: WORKING"
echo "   - Password authentication: DISABLED"
echo "   - IAM role credentials: AUTO-ROTATING"

echo "✅ Architecture Integrity:"
echo "   - Custom VPC: ISOLATED from default and other accounts"
echo "   - Network segmentation: PUBLIC/PRIVATE subnets configured"
echo "   - Defense in depth: MULTIPLE security layers active"
echo "   - Least privilege: MINIMAL permissions granted"
```

### **Expected Results:**
✅ **Network Security:** SSH works from your IP, blocked from others  
✅ **Access Control:** S3 access works, EC2/IAM access denied  
✅ **Authentication:** SSH key-based access functioning  
✅ **Credential Security:** No hardcoded credentials, automatic rotation  
✅ **Architecture Integrity:** All components properly configured and integrated  
✅ **Defense in Depth:** Multiple security layers all functioning correctly

---

## **🎯 Presentation Delivery Tips**

### **Before Starting Demos:**

#### **Console Preparation:**
1. **Open Multiple Browser Tabs:**
   - Main admin session (root/admin-user)
   - Incognito window for test-user
   - Have AWS services bookmarked: IAM, VPC, EC2, S3

2. **Prepare Your Environment:**
   ```bash
   # Get your public IP for security groups
   curl https://checkip.amazonaws.com
   
   # Test AWS CLI connectivity
   aws sts get-caller-identity
   
   # Prepare environment variables script
   cat > setup-vars.sh << 'EOF'
   #!/bin/bash
   export MY_IP=$(curl -s https://checkip.amazonaws.com)
   export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
   echo "Your IP: $MY_IP"
   echo "Account ID: $ACCOUNT_ID"
   EOF
   chmod +x setup-vars.sh
   ```

3. **Have Backup Screenshots:** Take screenshots of each major step in case live demos fail

### **During Presentation:**

#### **Demo Flow Strategy:**
1. **Start with Console for Visual Impact**
   - Show the GUI first so audience sees the interface
   - Explain what you're clicking and why
   - Highlight security implications of each setting

2. **Follow with CLI for Automation**
   - Show the equivalent CLI commands
   - Explain how this scales for automation
   - Demonstrate repeatability and infrastructure as code

3. **Validate Each Step**
   - Always test what you just configured
   - Show expected vs actual results
   - Explain what failure would look like

#### **Audience Engagement:**
1. **Console Method Benefits:**
   - "This is what you'll see in the AWS console"
   - "Notice the security warnings and recommendations"
   - "See how AWS guides you toward best practices"

2. **CLI Method Benefits:**
   - "This is how you automate at scale"
   - "These commands can be scripted and version controlled"
   - "DevOps teams use these for consistent deployments"

### **Troubleshooting Common Issues:**

#### **Demo 1 Issues:**
- **MFA setup fails:** Ensure phone time is synchronized
- **CLI configuration fails:** Check access key format and region

#### **Demo 2 Issues:**
- **Permissions don't take effect:** Wait 30 seconds for IAM propagation
- **Test user can't login:** Verify account ID in sign-in URL

#### **Demo 3 Issues:**
- **Role assumption fails:** Check trust policy has correct user ARN
- **EC2 instance profile fails:** Ensure instance profile contains the role

#### **Demo 4 Issues:**
- **Subnets can't reach internet:** Verify route table associations
- **DNS resolution fails:** Ensure DNS hostnames enabled on VPC

#### **Demo 5 Issues:**
- **NACL blocks traffic:** Remember both inbound AND outbound rules needed
- **Security group changes don't work:** Check if you're modifying the right group

#### **Demo 6 Issues:**
- **Instance launch fails:** Verify subnet has auto-assign public IP enabled
- **Can't SSH:** Check security group source IP (may have changed)

#### **Demo 7 Issues:**
- **S3 access fails:** Verify IAM role has S3ReadOnlyAccess policy
- **Instance can't assume role:** Check instance profile is attached

### **Recovery Strategies:**

#### **If Live Demo Fails:**
1. **Have pre-built resources ready:** Create a "backup" environment beforehand
2. **Use screenshots:** Show the expected results via prepared screenshots  
3. **Explain the concept:** Focus on the security principles even if demo fails
4. **Continue with working parts:** Skip problematic demos and continue with others

#### **If Console is Slow:**
1. **Switch to CLI:** Command line is usually faster and more reliable
2. **Use different region:** Some regions may be less busy
3. **Refresh browser:** Clear cache and cookies if console is unresponsive

### **Post-Demo Cleanup:**

#### **Resource Cleanup (Important for Cost!):**
```bash
# Clean up script - run after presentation
cat > cleanup.sh << 'EOF'
#!/bin/bash

# Terminate EC2 instances
aws ec2 terminate-instances --instance-ids $INSTANCE_ID

# Wait for termination
aws ec2 wait instance-terminated --instance-ids $INSTANCE_ID

# Delete key pair
aws ec2 delete-key-pair --key-name demo-key
rm -f demo-key.pem

# Delete security group
aws ec2 delete-security-group --group-id $SG_ID

# Delete custom NACL (reset to default first)
aws ec2 replace-network-acl-association --association-id $(aws ec2 describe-network-acls --filters "Name=vpc-id,Values=$VPC_ID" "Name=default,Values=false" --query 'NetworkAcls[0].Associations[0].NetworkAclAssociationId' --output text) --network-acl-id $(aws ec2 describe-network-acls --filters "Name=vpc-id,Values=$VPC_ID" "Name=default,Values=true" --query 'NetworkAcls[0].NetworkAclId' --output text)
aws ec2 delete-network-acl --network-acl-id $CUSTOM_NACL_ID

# Detach and delete internet gateway
aws ec2 detach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID
aws ec2 delete-internet-gateway --internet-gateway-id $IGW_ID

# Delete route table
aws ec2 delete-route-table --route-table-id $PUBLIC_RT_ID

# Delete subnets
aws ec2 delete-subnet --subnet-id $PUBLIC_SUBNET_ID
aws ec2 delete-subnet --subnet-id $PRIVATE_SUBNET_ID

# Delete VPC
aws ec2 delete-vpc --vpc-id $VPC_ID

# Clean up IAM resources
aws iam remove-role-from-instance-profile --instance-profile-name ec2-s3-profile --role-name iamroleec2s3
aws iam delete-instance-profile --instance-profile-name ec2-s3-profile
aws iam detach-role-policy --role-name iamroleec2s3 --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws iam delete-role --role-name iamroleec2s3
aws iam detach-role-policy --role-name iamroletests3 --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
aws iam delete-role --role-name iamroletests3

# Clean up users and groups
aws iam detach-user-policy --user-name test-user --policy-arn arn:aws:iam::$ACCOUNT_ID:policy/iampolicytests3full
aws iam delete-policy --policy-arn arn:aws:iam::$ACCOUNT_ID:policy/iampolicytests3full
aws iam remove-user-from-group --group-name iamreadonly --user-name test-user
aws iam detach-group-policy --group-name iamreadonly --policy-arn arn:aws:iam::aws:policy/IAMReadOnlyAccess
aws iam delete-group --group-name iamreadonly

# Delete access keys (get key IDs first)
TEST_USER_KEYS=$(aws iam list-access-keys --user-name test-user --query 'AccessKeyMetadata[].AccessKeyId' --output text)
for key in $TEST_USER_KEYS; do
    aws iam delete-access-key --user-name test-user --access-key-id $key
done

NEIL2_KEYS=$(aws iam list-access-keys --user-name neil2 --query 'AccessKeyMetadata[].AccessKeyId' --output text)
for key in $NEIL2_KEYS; do
    aws iam delete-access-key --user-name neil2 --access-key-id $key
done

# Delete login profiles
aws iam delete-login-profile --user-name test-user
aws iam delete-user --user-name test-user
aws iam delete-user --user-name neil2

echo "Cleanup completed! All demo resources have been removed."
EOF

chmod +x cleanup.sh
```

### **Final Presentation Checklist:**

#### **✅ Before Starting:**
- [ ] AWS CLI installed and configured
- [ ] Multiple browser tabs prepared
- [ ] Your public IP address noted
- [ ] Environment variables script ready
- [ ] Backup screenshots prepared
- [ ] Cleanup script ready

#### **✅ During Presentation:**
- [ ] Explain each security decision
- [ ] Show both console and CLI methods
- [ ] Validate each step with testing
- [ ] Engage audience with "what would happen if..." scenarios
- [ ] Document any deviations or issues for learning

#### **✅ After Presentation:**
- [ ] Run cleanup script to remove all resources
- [ ] Verify no charges will be incurred
- [ ] Save any valuable outputs or screenshots
- [ ] Document lessons learned for next time

This comprehensive guide gives you the flexibility to demonstrate AWS security architecture using both visual console interactions and scalable CLI automation, ensuring your presentation works for both technical and business audiences!