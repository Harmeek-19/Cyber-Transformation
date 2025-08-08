# AWS VPC Security Architecture Documentation

## Overview

This document covers the complete implementation of a secure AWS VPC infrastructure that I built as part of my cybersecurity learning journey. What started as a simple networking exercise quickly became an eye-opening experience into the complexity of cloud security. I'll walk you through what I built, the security decisions I made, and - honestly - the mistakes I made along the way.

## Architecture Summary

I created a custom VPC with public and private subnets, implementing multiple layers of security controls. The goal was to demonstrate "defense in depth" - the idea that no single security control should be your only protection. Think of it like having multiple locks on your front door, a security system, AND a guard dog.

---

## VPC Network Layout

### Core Network Design

**VPC CIDR Block:** `10.0.0.0/16`
- **Why I chose this:** It gives me 65,536 IP addresses to work with. Way more than I need for this demo, but it follows AWS best practices for enterprise environments.
- **Lesson learned:** Initially, I almost used `172.16.0.0/16` but realized this could conflict with corporate networks if I ever needed to connect via VPN.

### Subnet Architecture

#### Public Subnet: `10.0.1.0/24`
- **Location:** us-east-1a
- **IP Range:** 254 usable addresses
- **Purpose:** Hosts resources that need direct internet access
- **Key Feature:** Auto-assigns public IPv4 addresses

**What goes here:**
- EC2 instances that need internet access
- NAT Gateways (for future expansion)
- Load balancers (when I add them later)

#### Private Subnet: `10.0.2.0/24`
- **Location:** us-east-1b  
- **IP Range:** 254 usable addresses
- **Purpose:** Backend services with no direct internet access
- **Security Benefit:** Creates an isolated environment for sensitive resources

**What would go here:**
- Database servers
- Internal application servers
- Any service that shouldn't be directly reachable from the internet

### Network Routing

#### Public Route Table (`public-rt`)
- **Default route:** `0.0.0.0/0` → Internet Gateway
- **Local route:** `10.0.0.0/16` → Local (automatic)
- **Association:** public-subnet

#### Private Route Table (Default)
- **Local route only:** `10.0.0.0/16` → Local
- **No internet access:** This was intentional - private means private!
- **Future enhancement:** Would add NAT Gateway route for outbound-only internet access

---

## IAM Security Implementation

### EC2 Instance Profile: `ec2-s3-profile`

I created a custom IAM role for the EC2 instance because using root credentials or hardcoded keys is a massive security risk. For this VPC security demo, I kept the EC2 permissions minimal and focused on read-only access.

#### Why Read-Only for EC2?
- **s3:GetObject:** Can download files from the specific demo bucket only
- **s3:ListBucket:** Can see what files exist in the bucket
- **No write/delete permissions:** Follows principle of least privilege for infrastructure
- **Bucket-specific:** Can't access other S3 buckets in the account
- **Perfect for log collection or config file retrieval**

### Separate IAM User Demo (Full S3 Testing)

*Note: This was part of a separate S3 access demo, not directly related to the VPC infrastructure:*

#### User Role Permissions (Testing/Admin)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::demo-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Why Full Permissions for User Role?
- **Complete S3 management:** Can create, read, update, delete files
- **Account-wide bucket discovery:** Useful for testing and administration
- **Broader scope:** Appropriate for human administrators or testing scenarios
- **Different use case:** User access vs. automated system access require different permission models

#### What I Learned About IAM
- **Principle of Least Privilege:** Start with no permissions and add only what's needed
- **Instance Profiles vs. Roles:** The role defines permissions, the instance profile attaches it to EC2
- **Temporary Credentials:** IAM roles provide automatically rotating credentials - much safer than API keys
- **Different Access Patterns:** EC2 instances need minimal, focused permissions while human users may need broader access for administration
- **Separation of Concerns:** Infrastructure access (EC2) vs. administrative access (user roles) should have different permission models

---

## Multi-Layered Security Controls

Here's where I implemented the "defense in depth" concept with multiple security layers:

### Layer 1: Network ACLs (Subnet Level)

**NACL Name:** `demo-nacl`
**Applied to:** public-subnet only

#### Inbound Rules (Traffic Coming TO the EC2)
| Rule # | Protocol | Port Range | Source | Action | Purpose |
|--------|----------|------------|--------|---------|----------|
| 100 | TCP | 22 | My.IP.Address/32 | ALLOW | SSH access from my admin IP only |
| 200 | TCP | 1024-65535 | 0.0.0.0/0 | ALLOW | Return traffic for outbound connections |
| 300 | TCP | 443 | 0.0.0.0/0 | ALLOW | HTTPS responses from AWS services |

#### Outbound Rules (Traffic Going FROM the EC2)
| Rule # | Protocol | Port Range | Destination | Action | Purpose |
|--------|----------|------------|-------------|---------|----------|
| 100 | TCP | 1024-65535 | My.IP.Address/32 | ALLOW | SSH return traffic to my admin IP |
| 200 | TCP | 80 | 0.0.0.0/0 | ALLOW | HTTP requests (package updates) |
| 300 | TCP | 443 | 0.0.0.0/0 | ALLOW | HTTPS requests to AWS services |

**Why NACLs Are Tricky:**
- **Stateless:** Unlike security groups, NACLs don't automatically allow return traffic
- **Rule Order Matters:** Rules are processed in numerical order
- **Easy to Lock Yourself Out:** I initially forgot the return traffic rules and couldn't connect!

### Layer 2: Security Groups (Instance Level)

**Security Group Name:** `demo-sg-restrictive`

#### Inbound Rules
| Protocol | Port | Source | Purpose |
|----------|------|--------|----------|
| SSH (TCP) | 22 | My.IP.Address/32 | SSH access from admin workstation only |

#### Outbound Rules
| Protocol | Port | Destination | Purpose |
|----------|------|-------------|----------|
| All Traffic | All | 0.0.0.0/0 | Default - allows all outbound (can be restricted later) |

**Security Group Benefits:**
- **Stateful:** Automatically allows return traffic
- **Instance-specific:** Can be applied to multiple instances
- **Dynamic:** Can reference other security groups

### Layer 3: SSH Key Authentication

**Key Pair:** `demo-key` (RSA, .pem format)

#### Key Security Practices I Followed:
```bash
# Set proper permissions immediately after download
chmod 400 demo-key.pem

# Store in secure location (not in project repositories!)
mv demo-key.pem ~/.ssh/
```

**Why SSH Keys Are Critical:**
- **No Password Authentication:** Eliminates brute force password attacks
- **Cryptographic Security:** Much stronger than passwords
- **Unique Per Environment:** Each environment should have its own keys
