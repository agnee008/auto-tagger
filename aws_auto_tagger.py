"""
aws_auto_tagger.py - Intelligent AWS Resource Auto-Tagging System

Automatically tags AWS resources by inferring tags from naming patterns,
CloudTrail events, and existing tag patterns.

Author: Agnibes Banerjee
License: MIT

Usage:
    # Dry run (safe, no changes)
    python aws_auto_tagger.py --dry-run
    
    # Apply tags
    python aws_auto_tagger.py
    
    # Specific service only
    python aws_auto_tagger.py --service lambda
    
    # Generate report
    python aws_auto_tagger.py --report
"""

import boto3
import re
import os
import json
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SmartTagger:
    """
    Intelligent tag inference engine.
    Analyzes resource names and patterns to generate appropriate tags.
    """
    
    # Words that indicate team names
    TEAM_INDICATORS = [
        'payments', 'auth', 'data', 'analytics', 'platform',
        'security', 'infrastructure', 'mobile', 'web', 'api'
    ]
    
    # Words that are NOT team names
    EXCLUDED_WORDS = [
        'prod', 'dev', 'staging', 'test', 'lambda', 'ec2',
        'rds', 'api', 'service', 'function', 'database'
    ]
    
    def __init__(self):
        self.session = boto3.Session()
        self.cloudtrail = self.session.client('cloudtrail')
        self.sts = self.session.client('sts')
        self.account_id = self.sts.get_caller_identity()['Account']
    
    def infer_team_from_name(self, resource_name: str) -> Optional[str]:
        """
        Extract team name from resource naming convention.
        
        Patterns supported:
        - service-TEAM-description (e.g., lambda-payments-api)
        - TEAM-service-env (e.g., data-pipeline-prod)
        - service-description-TEAM (e.g., api-gateway-analytics)
        """
        name_lower = resource_name.lower()
        
        # Try different patterns
        patterns = [
            r'^[a-z0-9]+-([a-z]+)-',      # prefix-TEAM-suffix
            r'-([a-z]+)-(prod|dev|staging|test)',  # something-TEAM-env
            r'^([a-z]+)-[a-z0-9]+-',      # TEAM-prefix-suffix
        ]
        
        for pattern in patterns:
            match = re.search(pattern, name_lower)
            if match:
                potential_team = match.group(1)
                
                # Validate it's actually a team name
                if (potential_team not in self.EXCLUDED_WORDS and
                    len(potential_team) > 2):
                    return potential_team
        
        # Check if name contains known team indicators
        for team in self.TEAM_INDICATORS:
            if team in name_lower:
                return team
        
        return None
    
    def infer_environment(self, resource_name: str, account_id: str) -> str:
        """
        Infer environment from resource name or AWS account.
        """
        name_lower = resource_name.lower()
        
        # Check name for environment indicators
        env_patterns = {
            'production': ['prod', 'production', 'prd'],
            'development': ['dev', 'development'],
            'staging': ['staging', 'stage', 'stg'],
            'test': ['test', 'testing', 'tst']
        }
        
        for env, patterns in env_patterns.items():
            if any(p in name_lower for p in patterns):
                return env
        
        # Fall back to account-based detection
        # In real implementation, configure this mapping
        account_envs = {
            self.account_id: 'production'  # Default current account to prod
        }
        
        return account_envs.get(account_id, 'unknown')
    
    def get_creator_from_cloudtrail(self, 
                                    resource_name: str,
                                    service: str,
                                    max_age_days: int = 90) -> Optional[Dict]:
        """
        Look up resource creator from CloudTrail events.
        """
        try:
            # Map service to CloudTrail event name
            event_names = {
                'lambda': 'CreateFunction',
                'dynamodb': 'CreateTable',
                's3': 'CreateBucket',
                'ec2': 'RunInstances',
                'rds': 'CreateDBInstance'
            }
            
            event_name = event_names.get(service)
            if not event_name:
                return None
            
            # Search CloudTrail
            start_time = datetime.now() - timedelta(days=max_age_days)
            
            response = self.cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': event_name
                    }
                ],
                StartTime=start_time,
                MaxResults=50
            )
            
            # Find the event for this specific resource
            for event in response.get('Events', []):
                cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                
                # Check if this event is for our resource
                response_elements = cloud_trail_event.get('responseElements', {})
                if service == 'lambda':
                    if response_elements.get('functionName') == resource_name:
                        return self._extract_creator_info(event, cloud_trail_event)
                elif service == 'dynamodb':
                    table_desc = response_elements.get('tableDescription', {})
                    if table_desc.get('tableName') == resource_name:
                        return self._extract_creator_info(event, cloud_trail_event)
                elif service == 's3':
                    if resource_name in cloud_trail_event.get('requestParameters', {}).get('bucketName', ''):
                        return self._extract_creator_info(event, cloud_trail_event)
            
        except Exception as e:
            logger.debug(f"CloudTrail lookup failed for {resource_name}: {e}")
        
        return None
    
    def _extract_creator_info(self, event: Dict, cloud_trail_event: Dict) -> Dict:
        """Extract creator information from CloudTrail event."""
        username = event.get('Username', 'unknown')
        timestamp = event.get('EventTime')
        
        # Clean up username
        if '@' in username:
            owner = username.split('@')[0]
        elif '/' in username:
            owner = username.split('/')[-1]
        else:
            owner = username
        
        return {
            'owner': owner,
            'created_by': username,
            'created_date': timestamp.strftime('%Y-%m-%d'),
            'created_timestamp': timestamp.isoformat()
        }
    
    def generate_tags(self, resource: Dict) -> Dict[str, str]:
        """
        Generate intelligent tags for a resource.
        
        Args:
            resource: Dict with keys: name, arn, service, account_id, existing_tags
            
        Returns:
            Dict of tag key-value pairs
        """
        tags = {}
        
        resource_name = resource.get('name', '')
        service = resource.get('service', '')
        account_id = resource.get('account_id', self.account_id)
        
        # 1. Infer team from name
        team = self.infer_team_from_name(resource_name)
        if team:
            tags['Team'] = team.capitalize()
            tags['Project'] = f"{team}-services"
        
        # 2. Infer environment
        environment = self.infer_environment(resource_name, account_id)
        tags['Environment'] = environment.capitalize()
        
        # 3. Get creator information (expensive, so cache this)
        creator_info = self.get_creator_from_cloudtrail(resource_name, service)
        if creator_info:
            tags['Owner'] = creator_info['owner']
            tags['CreatedBy'] = creator_info['created_by']
            tags['CreatedDate'] = creator_info['created_date']
        
        # 4. Add management tags
        tags['ManagedBy'] = 'aws-auto-tagger'
        tags['LastTaggedDate'] = datetime.now().strftime('%Y-%m-%d')
        
        return tags


class ResourceScanner:
    """
    Scan AWS resources across multiple services.
    """
    
    def __init__(self, region: str = None):
        self.session = boto3.Session(region_name=region)
        self.region = region or self.session.region_name
    
    def scan_all(self, services: List[str] = None) -> List[Dict]:
        """
        Scan all supported AWS services.
        
        Args:
            services: List of service names to scan. If None, scan all.
        """
        if services is None:
            services = ['lambda', 'dynamodb', 's3', 'ec2']
        
        all_resources = []
        
        for service in services:
            logger.info(f"Scanning {service}...")
            try:
                resources = getattr(self, f'scan_{service}')()
                all_resources.extend(resources)
                logger.info(f"  Found {len(resources)} {service} resources")
            except Exception as e:
                logger.error(f"  Error scanning {service}: {e}")
        
        return all_resources
    
    def scan_lambda(self) -> List[Dict]:
        """Scan Lambda functions."""
        client = self.session.client('lambda')
        resources = []
        
        try:
            paginator = client.get_paginator('list_functions')
            for page in paginator.paginate():
                for func in page['Functions']:
                    resources.append({
                        'service': 'lambda',
                        'name': func['FunctionName'],
                        'arn': func['FunctionArn'],
                        'existing_tags': func.get('Tags', {}),
                        'account_id': func['FunctionArn'].split(':')[4],
                        'region': self.region
                    })
        except Exception as e:
            logger.error(f"Error scanning Lambda: {e}")
        
        return resources
    
    def scan_dynamodb(self) -> List[Dict]:
        """Scan DynamoDB tables."""
        client = self.session.client('dynamodb')
        resources = []
        
        try:
            paginator = client.get_paginator('list_tables')
            for page in paginator.paginate():
                for table_name in page['TableNames']:
                    # Get table details
                    table = client.describe_table(TableName=table_name)['Table']
                    
                    # Get tags
                    try:
                        tag_response = client.list_tags_of_resource(
                            ResourceArn=table['TableArn']
                        )
                        existing_tags = {
                            tag['Key']: tag['Value'] 
                            for tag in tag_response.get('Tags', [])
                        }
                    except:
                        existing_tags = {}
                    
                    resources.append({
                        'service': 'dynamodb',
                        'name': table_name,
                        'arn': table['TableArn'],
                        'existing_tags': existing_tags,
                        'account_id': table['TableArn'].split(':')[4],
                        'region': self.region
                    })
        except Exception as e:
            logger.error(f"Error scanning DynamoDB: {e}")
        
        return resources
    
    def scan_s3(self) -> List[Dict]:
        """Scan S3 buckets."""
        client = self.session.client('s3')
        resources = []
        
        try:
            response = client.list_buckets()
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                
                # Get tags
                try:
                    tag_response = client.get_bucket_tagging(Bucket=bucket_name)
                    existing_tags = {
                        tag['Key']: tag['Value']
                        for tag in tag_response['TagSet']
                    }
                except:
                    existing_tags = {}
                
                # Get account ID
                sts = boto3.client('sts')
                account_id = sts.get_caller_identity()['Account']
                
                resources.append({
                    'service': 's3',
                    'name': bucket_name,
                    'arn': f"arn:aws:s3:::{bucket_name}",
                    'existing_tags': existing_tags,
                    'account_id': account_id,
                    'region': 'global'  # S3 is global
                })
        except Exception as e:
            logger.error(f"Error scanning S3: {e}")
        
        return resources
    
    def scan_ec2(self) -> List[Dict]:
        """Scan EC2 instances."""
        client = self.session.client('ec2')
        resources = []
        
        try:
            paginator = client.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        # Skip terminated instances
                        if instance['State']['Name'] == 'terminated':
                            continue
                        
                        # Get name from tags
                        name = instance['InstanceId']
                        existing_tags = {}
                        
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                            existing_tags[tag['Key']] = tag['Value']
                        
                        resources.append({
                            'service': 'ec2',
                            'name': name,
                            'arn': f"arn:aws:ec2:{self.region}:{instance['OwnerId']}:instance/{instance['InstanceId']}",
                            'instance_id': instance['InstanceId'],
                            'existing_tags': existing_tags,
                            'account_id': instance['OwnerId'],
                            'region': self.region
                        })
        except Exception as e:
            logger.error(f"Error scanning EC2: {e}")
        
        return resources


class TaggingExecutor:
    """
    Execute tagging operations with safety checks and dry-run support.
    """
    
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.session = boto3.Session()
    
    def apply_tags(self, resource: Dict, tags: Dict[str, str]) -> Tuple[bool, str]:
        """
        Apply tags to a resource.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        service = resource['service']
        name = resource['name']
        existing = resource.get('existing_tags', {})
        
        # Filter out tags that already exist with same value
        new_tags = {
            k: v for k, v in tags.items()
            if k not in existing or existing[k] != v
        }
        
        if not new_tags:
            return False, f"Already tagged: {name}"
        
        if self.dry_run:
            return False, f"DRY RUN - Would tag {name}: {new_tags}"
        
        # Apply tags based on service
        try:
            if service == 'lambda':
                self._tag_lambda(resource['arn'], new_tags)
            elif service == 'dynamodb':
                self._tag_dynamodb(resource['arn'], new_tags)
            elif service == 's3':
                self._tag_s3(name, new_tags, existing)
            elif service == 'ec2':
                self._tag_ec2(resource['instance_id'], new_tags)
            else:
                return False, f"Unsupported service: {service}"
            
            return True, f"Tagged {name}: {new_tags}"
            
        except Exception as e:
            return False, f"Failed to tag {name}: {str(e)}"
    
    def _tag_lambda(self, function_arn: str, tags: Dict):
        """Tag Lambda function."""
        client = self.session.client('lambda')
        client.tag_resource(Resource=function_arn, Tags=tags)
    
    def _tag_dynamodb(self, table_arn: str, tags: Dict):
        """Tag DynamoDB table."""
        client = self.session.client('dynamodb')
        tag_list = [{'Key': k, 'Value': v} for k, v in tags.items()]
        client.tag_resource(ResourceArn=table_arn, Tags=tag_list)
    
    def _tag_s3(self, bucket_name: str, new_tags: Dict, existing_tags: Dict):
        """Tag S3 bucket."""
        client = self.session.client('s3')
        
        # Merge with existing
        all_tags = {**existing_tags, **new_tags}
        tag_set = [{'Key': k, 'Value': v} for k, v in all_tags.items()]
        
        client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={'TagSet': tag_set}
        )
    
    def _tag_ec2(self, instance_id: str, tags: Dict):
        """Tag EC2 instance."""
        client = self.session.client('ec2')
        tag_list = [{'Key': k, 'Value': v} for k, v in tags.items()]
        client.create_tags(Resources=[instance_id], Tags=tag_list)


class AutoTagger:
    """
    Main auto-tagging orchestrator.
    """
    
    def __init__(self, dry_run: bool = True, region: str = None):
        self.dry_run = dry_run
        self.region = region
        self.scanner = ResourceScanner(region)
        self.tagger = SmartTagger()
        self.executor = TaggingExecutor(dry_run)
    
    def run(self, services: List[str] = None) -> Dict:
        """
        Run the auto-tagging process.
        
        Returns:
            Dict with statistics
        """
        logger.info("="*60)
        logger.info("AWS Auto-Tagger Starting")
        logger.info(f"Mode: {'DRY RUN' if self.dry_run else 'LIVE'}")
        logger.info(f"Region: {self.region or 'default'}")
        logger.info("="*60)
        
        # Scan resources
        logger.info("\nScanning AWS resources...")
        resources = self.scanner.scan_all(services)
        logger.info(f"Found {len(resources)} total resources\n")
        
        # Track statistics
        stats = {
            'total': len(resources),
            'tagged': 0,
            'already_tagged': 0,
            'failed': 0,
            'by_service': defaultdict(int)
        }
        
        # Process each resource
        for i, resource in enumerate(resources, 1):
            service = resource['service']
            name = resource['name']
            
            logger.info(f"[{i}/{len(resources)}] Processing {service}: {name}")
            
            # Check if required tags exist
            existing = resource.get('existing_tags', {})
            required_tags = ['Team', 'Environment', 'ManagedBy']
            
            if all(tag in existing for tag in required_tags):
                logger.info(f"  ✓ Already fully tagged")
                stats['already_tagged'] += 1
                continue
            
            # Generate tags
            generated_tags = self.tagger.generate_tags(resource)
            
            # Apply tags
            success, message = self.executor.apply_tags(resource, generated_tags)
            
            if success:
                logger.info(f"  ✓ {message}")
                stats['tagged'] += 1
                stats['by_service'][service] += 1
            elif self.dry_run and 'Would tag' in message:
                logger.info(f"  🔍 {message}")
                stats['tagged'] += 1
                stats['by_service'][service] += 1
            else:
                logger.info(f"  ⏭️  {message}")
        
        # Print summary
        self._print_summary(stats)
        
        return stats
    
    def _print_summary(self, stats: Dict):
        """Print execution summary."""
        logger.info("\n" + "="*60)
        logger.info("SUMMARY")
        logger.info("="*60)
        logger.info(f"Total resources: {stats['total']}")
        logger.info(f"Tagged: {stats['tagged']}")
        logger.info(f"Already tagged: {stats['already_tagged']}")
        logger.info(f"Failed: {stats['failed']}")
        
        if stats['by_service']:
            logger.info("\nBy Service:")
            for service, count in stats['by_service'].items():
                logger.info(f"  {service}: {count}")
        
        if self.dry_run:
            logger.info("\n⚠️  DRY RUN - No changes were made")
            logger.info("Run without --dry-run to apply tags")


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Intelligent AWS resource auto-tagger'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run in dry-run mode (no changes)'
    )
    parser.add_argument(
        '--service',
        type=str,
        help='Specific service to scan (lambda, dynamodb, s3, ec2)'
    )
    parser.add_argument(
        '--region',
        type=str,
        help='AWS region (default: current session region)'
    )
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate tagging compliance report'
    )
    
    args = parser.parse_args()
    
    # Determine services to scan
    services = [args.service] if args.service else None
    
    # Run auto-tagger
    tagger = AutoTagger(
        dry_run=args.dry_run,
        region=args.region
    )
    
    stats = tagger.run(services)
    
    # Generate report if requested
    if args.report:
        generate_compliance_report(stats)


def generate_compliance_report(stats: Dict):
    """Generate compliance report."""
    total = stats['total']
    tagged = stats['tagged'] + stats['already_tagged']
    coverage = (tagged / total * 100) if total > 0 else 0
    
    report = f"""
AWS Tagging Compliance Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Coverage: {coverage:.1f}%
Total Resources: {total}
Fully Tagged: {tagged}
Needs Tags: {total - tagged}

By Service:
"""
    
    for service, count in stats.get('by_service', {}).items():
        report += f"  {service}: {count}\n"
    
    print(report)


if __name__ == '__main__':
    main()
