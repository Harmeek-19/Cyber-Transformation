
# Failed Approaches to Generate Real GuardDuty Security Incidents

## Overview
Documentation of attempted methods to generate authentic GuardDuty findings beyond sample findings, including technical challenges and failure analysis.

## Method 1: Manual DNS-Based Activity Generation

### Approach
```bash
# Basic DNS queries to known malicious domains
nslookup guarddutyc2activityb.com
nslookup malware.testcategory.guardduty.com
nslookup pool.minergate.com
nslookup mining.bitcoin.cz
```

### Expected Result
- DNS-based findings: `Trojan:EC2/DNSDataExfiltration`
- Cryptocurrency findings: `CryptoCurrency:EC2/BitcoinTool.B!DNS`

### Actual Result
- No new findings generated after 2+ hours
- Existing sample findings remained unchanged at 363





## Method 3: GuardDuty Tester Script (CDK-Based)

### Approach
```bash
# Download and deploy official AWS GuardDuty Tester
wget https://github.com/awslabs/amazon-guardduty-tester/archive/master.zip
npm install
npx cdk deploy --profile admin-mfa
```

### Expected Result
- Automated EC2 deployment with malicious activity simulation
- Multiple finding types generated through realistic scenarios

### Actual Result
- CDK version compatibility errors
- Node.js version deprecation warnings
- Docker dependency issues in WSL environment


## Method 4: Bash Script Execution from Tester Repository

### Approach
```bash
# Navigate to scenario scripts
cd ~/amazon-guardduty-tester-master/lib/common/testResources/scenarios/ec2/
chmod +x *.sh
./DNSDataExfiltration.sh
./DenialOfService-DNS.sh
```

### Expected Result
- Direct execution of AWS-provided attack simulation scripts
- Realistic finding generation through proven scenarios

### Actual Result
- Scripts executed but showed dependency errors
- Required specific EC2 environment and additional tools
- No findings generated from local execution


## Method 5: Python-Based GuardDuty Tester

### Approach
```python
# Direct execution of Python tester components
python3 guardduty_tester.py --help
python3 simple_gd_test.py
```

### Expected Result
- Programmatic generation of suspicious activities
- Better control over timing and activity patterns

### Actual Result
- Python scripts required additional configuration
- Missing required parameters and AWS resource contexts
- No findings generated through Python execution


## Method 6: EC2 Instance Creation for Real Activity

### Approach
```bash
# Create EC2 instance with user data script for malicious activity
aws ec2 run-instances \
    --image-id ami-0abcdef1234567890 \
    --instance-type t2.micro \
    --user-data "#!/bin/bash
nslookup pool.minergate.com
curl -s http://guarddutyc2activityb.com"
```

### Expected Result
- Real EC2-sourced network activity
- Authentic behavioral patterns for GuardDuty analysis

### Actual Result
- Attempted but not fully implemented due to:
  - AMI ID validation issues
  - Security group configuration requirements
  - Cost considerations for training environment



## Method 7: API-Based Suspicious Activity Generation

### Approach
```bash
# Generate rapid API calls to simulate reconnaissance
for i in {1..10}; do
    aws iam list-users --profile admin-mfa
    aws iam list-roles --profile admin-mfa
    aws s3api list-buckets --profile admin-mfa
    sleep 1
done
```

### Expected Result
- `Recon:IAMUser/MaliciousIPCaller` findings
- Behavioral anomaly detection through API patterns

### Actual Result
- API calls executed successfully
- No unusual activity flags generated
- Normal administrative pattern, not recognized as malicious



The failed attempts provide valuable insight into GuardDuty's operational requirements and the sophistication of AWS security services in distinguishing between legitimate training activities and actual security threats.
