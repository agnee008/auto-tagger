# AWS Auto-Tagger

Intelligent AWS resource tagging system that automatically tags your resources by inferring tags from naming patterns, CloudTrail events, and existing tag patterns.

## The Problem

- Developers forget to tag resources
- Manual tagging is tedious and doesn't scale
- Tags drift over time
- No visibility into who owns what
- Compliance audits fail due to missing tags
- Can't track costs by team/project

## The Solution

Auto-Tagger scans all your AWS resources and intelligently generates tags based on:

- **Naming patterns** - Extracts team/environment from resource names
- **CloudTrail events** - Finds who created each resource
- **Existing patterns** - Learns from your current tagging conventions
- **VPC inheritance** - Resources inherit tags from their VPC
- **Account mapping** - Maps AWS accounts to environments

## Features

✅ **Smart Tag Inference** - Learns from your naming conventions  
✅ **CloudTrail Integration** - Automatic owner detection  
✅ **Multi-Service Support** - Lambda, DynamoDB, S3, EC2, and more  
✅ **Dry-Run Mode** - Test before applying changes  
✅ **Compliance Reports** - Track tagging coverage over time  
✅ **Daily Automation** - Run via EventBridge schedule  
✅ **Slack Notifications** - Daily reports on tagging status  

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/agnee008/aws-auto-tagger.git
cd aws-auto-tagger

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure
```

### Usage

```bash
# Dry run (safe, no changes)
python aws_auto_tagger.py --dry-run

# Tag specific service
python aws_auto_tagger.py --service lambda --dry-run

# Apply tags (live mode)
python aws_auto_tagger.py

# Generate compliance report
python aws_auto_tagger.py --report
```

## How It Works

### 1. Pattern-Based Tag Inference

The tool analyzes resource names to extract team and environment:

**Examples:**
- `lambda-payments-api` → Team: payments, Environment: production
- `dynamodb-analytics-dev` → Team: analytics, Environment: development
- `s3-data-platform-staging` → Team: data, Environment: staging

### 2. CloudTrail Owner Detection

Looks up CloudTrail events to find who created each resource:

```python
# Automatically tagged:
Owner: agni.banerjee
CreatedBy: agni.banerjee@company.com
CreatedDate: 2024-02-14
```

### 3. Smart Tag Application

Only adds tags that don't exist. Never overwrites existing tags.

```
Existing tags: {Environment: production}
Generated tags: {Team: payments, Owner: alice}
Result: Both tags applied, Environment not changed
```

## Supported AWS Services

- ✅ AWS Lambda
- ✅ Amazon DynamoDB
- ✅ Amazon S3
- ✅ Amazon EC2
- ⏳ Amazon RDS (coming soon)
- ⏳ Amazon ECS (coming soon)
- ⏳ Amazon SQS (coming soon)

## Tag Schema

Auto-generated tags:

| Tag | Source | Example |
|-----|--------|---------|
| Team | Resource name pattern | payments |
| Environment | Name or account | production |
| Owner | CloudTrail event | agni.banerjee |
| CreatedBy | CloudTrail event | agni.banerjee@company.com |
| CreatedDate | CloudTrail event | 2024-02-14 |
| ManagedBy | Auto-tagger | aws-auto-tagger |
| LastTaggedDate | Current date | 2024-02-14 |

## Deployment

### Run Daily via EventBridge

1. **Create Lambda function** with this code
2. **Set up EventBridge rule** to trigger daily
3. **Configure IAM permissions** for tagging
4. **Optional:** Add Slack webhook for notifications

See `deployment/` folder for:
- CloudFormation template
- Lambda handler
- IAM policies
- EventBridge schedule

### Local Development

```bash
# Run tests
pytest tests/

# Run with debug logging
python aws_auto_tagger.py --dry-run --verbose

# Test specific region
python aws_auto_tagger.py --region us-east-1 --dry-run
```

## Configuration

### Customize Team Detection

Edit `TEAM_INDICATORS` in `aws_auto_tagger.py`:

```python
TEAM_INDICATORS = [
    'payments', 'auth', 'data', 'analytics',
    'your-team-here'  # Add your teams
]
```

### Customize Account Mapping

Map AWS accounts to environments:

```python
account_envs = {
    '111111111111': 'production',
    '222222222222': 'development',
    '333333333333': 'staging'
}
```

### Exclusion List

Exclude specific resources from auto-tagging:

```python
EXCLUDED_RESOURCES = [
    'cloudformation-*',  # CF stacks
    'aws-*',             # AWS managed
]
```

## Real-World Results

**Before Auto-Tagger:**
- 30% of resources tagged
- 10 hours/week manual tagging
- Failed compliance audit

**After Auto-Tagger:**
- 95% of resources tagged
- 0 hours/week manual tagging
- Passed audit with zero findings
- Found £13K/month in orphaned resources

## Cost

**Running Cost:** ~£3/month
- Lambda invocations
- CloudTrail API calls
- S3 for reports

**Time Saved:** 10+ hours/week  
**ROI:** Immediate

## Common Issues

### Issue: "Access Denied" errors

**Solution:** Ensure IAM role has these permissions:
- `tag:GetResources`
- `tag:TagResources`
- `cloudtrail:LookupEvents`
- Service-specific read permissions

### Issue: Tags not appearing

**Solution:** 
- Check dry-run mode is off
- Verify IAM permissions
- Some resources take time to reflect tags

### Issue: CloudTrail lookup slow

**Solution:**
- CloudTrail queries can be slow for old resources
- Consider caching creator info
- Adjust `max_age_days` parameter

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## License

MIT License - see LICENSE file

## Author

**Agnibes Banerjee**  
Lead AWS Data Engineer

- LinkedIn: [linkedin.com/in/agnibeshbanerjee](https://linkedin.com/in/agnibeshbanerjee)
- GitHub: [@agnibes](https://github.com/agnibes)
- Medium: [@agnibes](https://medium.com/@agnibes)

## Support

- 🐛 Report bugs via GitHub Issues
- 💡 Request features via GitHub Issues
- 📧 Email: agnee008@gmail.com

## Acknowledgments

Built to solve real compliance and cost visibility problems in production AWS environments.

---

**Stop manually tagging. Start auto-tagging.** ⚡
