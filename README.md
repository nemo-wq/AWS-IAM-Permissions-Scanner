# AWS IAM Permissions Scan

This tool lists all policies assigned to all IAM users in your AWS account. Policies can be assigned to users via user policies or inherited by group memberships. 

Read only permissions to IAM in the AWS account being scanned are required. This can be achieved by assigning the SecurityAudit AWS Managed policy to the IAM user or role being used to run this scan. 

There are existing tools that go through potential privilege escalation avenues due to excessive AWS permissions. This script therefore complements rather than replaces some of these tools, such as Rhino Security's [AWS Escalate](https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/aws-pentest-tools/aws_escalate.py), NCC Group's [Scout2](https://github.com/nccgroup/Scout2), or [CloudSploit](https://github.com/cloudsploit).

## Getting Started

This script requires Python 3

Install the AWS Python SDK and Dependencies. [Details](https://github.com/boto/boto3)

 ```
 pip install boto3
 ```

Further details can be found [here](https://aws.amazon.com/developers/getting-started/python/)

Setup your AWS credentials. If you have awscli installed, running `aws configure` will prompt you for your AWS Access Key ID and your Secret Key, and create the `~/.aws/credentials` file. Alternatively, the `~/.aws/credentials` file can be configured as shown in the below example:

```
[default]
aws_access_key_id = AWS_KEY
aws_secret_access_key = AWS_SECRET
```

If you need to assume an IAM role and then scan for assigned permissions, remind101's assume-role tool is very helpful, especially is you are required to provide MFA. [Link](https://github.com/remind101/assume-role)

Install [Colorama](https://pypi.org/project/colorama/)

```
pip install colorama
```

### Running

```
python ./aws_perms.py
```
