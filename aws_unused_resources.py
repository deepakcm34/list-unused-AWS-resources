import boto3
from datetime import datetime, timedelta, timezone
import logging
import itertools
import uuid
from jinja2 import Template
import os
import requests
import sys


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CloudWatchWrapper:

    def __init__(self, cloudwatch_client):
        self.cloudwatch_client = cloudwatch_client

    def list_metrics(self, namespace, dimensions):
        metrics = []
        try:
            paginator = self.cloudwatch_client.get_paginator('list_metrics')
            for page in paginator.paginate(Namespace=namespace, Dimensions=dimensions):
                metrics.extend(page['Metrics'])
        except Exception as e:
            logger.exception(f"Couldn't get metrics for {namespace} with dimensions {dimensions}. Error: {e}")
            raise
        return metrics

    def get_metric_data(self, queries, start_time, end_time):
        results = []
        try:
            paginator = self.cloudwatch_client.get_paginator('get_metric_data')
            for page in paginator.paginate(MetricDataQueries=queries, StartTime=start_time, EndTime=end_time):
                results.extend(page['MetricDataResults'])
        except Exception as e:
            logger.exception(f"Couldn't get metric data. Error: {e}")
            raise
        return results

    def get_metric_statistics(self, namespace, metric_name, dimensions, start_time, end_time, period=86400):
        try:
            return self.cloudwatch_client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start_time,
                EndTime=end_time,
                Period=period,
                Statistics=['Average']
            )['Datapoints']
        except Exception as e:
            logger.exception(f"Couldn't get metric statistics for {metric_name} in {namespace}. Error: {e}")
            raise


def initialize_aws_clients():
    ec2_client = boto3.client('ec2', region_name=os.environ['AWS_REGION'])
    elb_client = boto3.client('elb', region_name=os.environ['AWS_REGION'])
    elbv2_client = boto3.client('elbv2', region_name=os.environ['AWS_REGION'])
    rds_client = boto3.client('rds', region_name=os.environ['AWS_REGION'])
    cloudwatch_client = boto3.client('cloudwatch', region_name=os.environ['AWS_REGION'])
    iam_client = boto3.client('iam')
    autoscaling_client = boto3.client('autoscaling', region_name=os.environ['AWS_REGION'])
    lambda_client = boto3.client('lambda', region_name=os.environ['AWS_REGION'])
    opensearch_client = boto3.client('opensearch', region_name=os.environ['AWS_REGION'])
    elasticache_client = boto3.client('elasticache', region_name=os.environ['AWS_REGION'])
    cloudfront_client = boto3.client('cloudfront')
    s3_client = boto3.client('s3', 
                             region_name=os.environ['AWS_REGION'],
                             aws_access_key_id=os.environ['S3_ACCESS_KEY_ID'],
                             aws_secret_access_key=os.environ['S3_SECRET_ACCESS_KEY'])
    return (ec2_client, elb_client, elbv2_client, rds_client, cloudwatch_client, iam_client, 
            autoscaling_client, lambda_client, opensearch_client, elasticache_client, cloudfront_client, s3_client)

def list_unattached_ebs_volumes(ec2_client):
    volumes = ec2_client.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])
    unattached_volumes = []
    for volume in volumes['Volumes']:
        volume_info = {
            'VolumeId': volume['VolumeId'],
            'Size': volume['Size'],
            'Name': 'N/A',
            'Description': 'N/A'
        }
        if 'Tags' in volume:
            for tag in volume['Tags']:
                if tag['Key'] == 'Name':
                    volume_info['Name'] = tag['Value']
                if tag['Key'] == 'Description':
                    volume_info['Description'] = tag['Value']
        unattached_volumes.append(volume_info)
    return unattached_volumes

def list_unused_elastic_ips(ec2_client):
    addresses = ec2_client.describe_addresses()['Addresses']
    return [{"PublicIp": address['PublicIp']} for address in addresses if 'InstanceId' not in address and 'NetworkInterfaceId' not in address and 'AssociationId' not in address]

def list_unassociated_elbs(elb_client):
    elbs = elb_client.describe_load_balancers()['LoadBalancerDescriptions']
    return [{"LoadBalancerName": elb['LoadBalancerName']} for elb in elbs if not elb['Instances']]

def list_idle_rds_instances(rds_client, cloudwatch_wrapper):
    instances = rds_client.describe_db_instances()['DBInstances']
    idle_instances = []

    for instance in instances:
        db_instance_identifier = instance['DBInstanceIdentifier']
        state = instance['DBInstanceStatus']

        if state == 'stopped':
            idle_instances.append({"DBInstanceIdentifier": db_instance_identifier})
        elif state == 'available':
            connection_metrics = cloudwatch_wrapper.get_metric_statistics(
                namespace='AWS/RDS',
                metric_name='DatabaseConnections',
                dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_instance_identifier}],
                start_time=datetime.now(timezone.utc) - timedelta(days=10),
                end_time=datetime.now(timezone.utc),
                period=86400
            )
            average_connections = sum([point['Average'] for point in connection_metrics]) / len(connection_metrics) if connection_metrics else 0

            if average_connections == 0:
                idle_instances.append({"DBInstanceIdentifier": db_instance_identifier})

    return idle_instances

def list_unused_elbv2(elbv2_client):
    load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']
    unused_load_balancers = []

    for lb in load_balancers:
        target_groups = elbv2_client.describe_target_groups(LoadBalancerArn=lb['LoadBalancerArn'])['TargetGroups']
        targets_exist = any(elbv2_client.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])['TargetHealthDescriptions'] for tg in target_groups)
        
        if not targets_exist:
            lb_info = {
                'LoadBalancerName': lb['LoadBalancerName'],
                'Name': 'N/A',
                'Description': 'N/A'
            }
            # Fetch tags for the load balancer
            tags_response = elbv2_client.describe_tags(ResourceArns=[lb['LoadBalancerArn']])
            for tag_description in tags_response['TagDescriptions']:
                for tag in tag_description['Tags']:
                    if tag['Key'] == 'Name':
                        lb_info['Name'] = tag['Value']
                    if tag['Key'] == 'Description':
                        lb_info['Description'] = tag['Value']
            unused_load_balancers.append(lb_info)

    return unused_load_balancers

def list_idle_ec2_instances(ec2_client, cloudwatch_wrapper, network_threshold=10):
    instances = ec2_client.describe_instances()['Reservations']
    idle_instances = []

    for reservation in instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            state = instance['State']['Name']
            name = 'N/A'
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    name = tag['Value']
                    break

            if state == 'stopped':
                idle_instances.append({"InstanceId": instance_id, "Name": name, "State": state})
            elif state == 'running':
                network_in_metrics = cloudwatch_wrapper.get_metric_statistics(
                    namespace='AWS/EC2',
                    metric_name='NetworkPacketsIn',
                    dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                    start_time=datetime.now(timezone.utc) - timedelta(days=10),
                    end_time=datetime.now(timezone.utc),
                    period=86400
                )
                average_network_in = sum([point['Average'] for point in network_in_metrics]) / len(network_in_metrics) if network_in_metrics else 0

                if average_network_in < network_threshold:
                    idle_instances.append({"InstanceId": instance_id, "Name": name, "State": state})

    return idle_instances


def list_unused_iam_roles(iam_client):
    roles = iam_client.list_roles()['Roles']
    used_roles = set()
    unused_roles = []
    six_months_ago = datetime.now(timezone.utc) - timedelta(days=180)

    for role in roles:
        attached_policies = iam_client.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
        if attached_policies:
            used_roles.add(role['RoleName'])
        else:
            last_used = iam_client.get_role(RoleName=role['RoleName'])['Role']['RoleLastUsed']
            last_used_date = last_used.get('LastUsedDate', None)
            if last_used_date is None or last_used_date < six_months_ago:
                last_used_date_str = last_used_date.strftime('%Y-%m-%d') if last_used_date else 'Never'
                unused_roles.append({"RoleName": role['RoleName'], "LastUsedDate": last_used_date_str})

    if not unused_roles:
        unused_roles.append({"RoleName": "No roles found unused older than 6 months", "LastUsedDate": ""})

    return unused_roles


def list_unused_autoscaling_groups(autoscaling_client):
    groups = autoscaling_client.describe_auto_scaling_groups()['AutoScalingGroups']
    return [{"AutoScalingGroupName": group['AutoScalingGroupName']} for group in groups if group['DesiredCapacity'] == 0]

def list_unused_lambda_functions(lambda_client, cloudwatch_client):
    functions = lambda_client.list_functions()['Functions']
    unused_functions = []

    for function in functions:
        metrics = cloudwatch_client.get_metric_statistics(
            Namespace='AWS/Lambda',
            MetricName='Invocations',
            Dimensions=[{'Name': 'FunctionName', 'Value': function['FunctionName']}],
            StartTime=datetime.now(timezone.utc) - timedelta(days=90),
            EndTime=datetime.now(timezone.utc),
            Period=86400,
            Statistics=['Sum']
        )['Datapoints']
        if not any(metric['Sum'] > 0 for metric in metrics):
            unused_functions.append({"FunctionName": function['FunctionName']})

    return unused_functions

def get_active_amis(ec2_client):
    """
    Retrieve all AMIs currently used by running EC2 instances.
    """
    active_amis = set()
    paginator = ec2_client.get_paginator('describe_instances')
    try:
        for page in paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]):
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    ami_id = instance['ImageId']
                    active_amis.add(ami_id)
                    logger.info(f"Found active AMI: {ami_id}")
    except Exception as e:
        logger.error("Error retrieving active AMIs: {}".format(e))
        raise
    return active_amis

def list_old_ebs_snapshots(ec2_client):
    """
    List EBS snapshots older than 30 days, excluding those linked to AMIs currently in use.
    """
    snapshots = ec2_client.describe_snapshots(OwnerIds=['self'])['Snapshots']
    one_month_ago = datetime.now(timezone.utc) - timedelta(days=30)
    active_amis = get_active_amis(ec2_client)  # Retrieve active AMIs in use by EC2 instances

    # Retrieve snapshots used by active AMIs from block device mappings
    active_snapshot_ids = set()
    for ami_id in active_amis:
        ami_details = ec2_client.describe_images(ImageIds=[ami_id])
        if ami_details['Images']:  # Check if list is not empty
            ami_image = ami_details['Images'][0]
            for block_device in ami_image.get('BlockDeviceMappings', []):
                if 'Ebs' in block_device and 'SnapshotId' in block_device['Ebs']:
                    active_snapshot_ids.add(block_device['Ebs']['SnapshotId'])

    snapshot_details = []
    for snap in snapshots:
        if snap['StartTime'] < one_month_ago and snap['SnapshotId'] not in active_snapshot_ids:
            # Only list snapshots that are not in active_snapshot_ids
            name = next((tag['Value'] for tag in snap.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')

            snapshot_details.append({
                'SnapshotId': snap['SnapshotId'],
                'Name': name,
                'StartTime': snap['StartTime'].strftime('%Y-%m-%d %H:%M:%S'),  # formatting date
                'AmiId': 'N/A'  # Not directly relevant here
            })

    return snapshot_details


def list_old_amis(ec2_client):
    """
    List AMIs that are older than 30 days and not in use by any EC2 instances.
    """
    one_month_ago = datetime.now(timezone.utc) - timedelta(days=30)
    old_images = []
    active_amis = get_active_amis(ec2_client)  # Retrieve active AMIs in use by EC2 instances

    logger.info(f"Active AMIs: {active_amis}")

    images = ec2_client.describe_images(Owners=['self'])['Images']
    for image in images:
        creation_date = datetime.strptime(image['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
        if creation_date < one_month_ago and image['ImageId'] not in active_amis:
            name = next((tag['Value'] for tag in image.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
            old_images.append({"ImageId": image['ImageId'], "Name": name, "CreationDate": image['CreationDate']})
            logger.info(f"Listing old, unused AMI: {image['ImageId']}")
        else:
            logger.info(f"Skipping AMI in use: {image['ImageId']}")

    return old_images



def list_unused_opensearch_domains(opensearch_client, cloudwatch_wrapper):
    try:
        domains = opensearch_client.list_domain_names()['DomainNames']
        unused_domains = []

        for domain in domains:
            domain_name = domain['DomainName']
            region = os.environ['AWS_REGION']
            try:
                domain_status = opensearch_client.describe_domain(DomainName=domain_name)['DomainStatus']
            except KeyError:
                logger.warning(f"DomainStatus key not found for domain: {domain_name}")
                continue

            if domain_status.get('Processing', True) or 'EngineVersion' not in domain_status:
                continue

            dimensions = [{'Name': 'DomainName', 'Value': domain_name}]
            available_metrics = cloudwatch_wrapper.list_metrics(namespace='AWS/ES', dimensions=dimensions)

            queries = build_metric_data_queries(domain_name, region, available_metrics)
            start_time = datetime.now(timezone.utc) - timedelta(days=10)
            end_time = datetime.now(timezone.utc)

            search_rate_data = []
            indexing_rate_data = []

            for group in grouper(queries, 100):
                results = cloudwatch_wrapper.get_metric_data(queries=group, start_time=start_time, end_time=end_time)
                for result in results:
                    if result['Values']:
                        if 'SearchRate' in result['Label']:
                            search_rate_data.extend(result['Values'])
                        elif 'IndexingRate' in result['Label']:
                            indexing_rate_data.extend(result['Values'])
                    else:
                        logger.info(f"No data for metric: {result['Label']}")

            avg_search_rate = sum(search_rate_data) / len(search_rate_data) if search_rate_data else 0
            avg_indexing_rate = sum(indexing_rate_data) / len(indexing_rate_data) if indexing_rate_data else 0

            if avg_search_rate == 0 and avg_indexing_rate == 0:
                unused_domains.append({
                    "DomainName": domain_name,
                    "AverageSearchRate": avg_search_rate,
                    "AverageIndexingRate": avg_indexing_rate
                })

        return unused_domains

    except Exception as e:
        logger.error(f"Error listing OpenSearch domain usage: {e}")
        return []


def list_unused_elasticache_clusters(elasticache_client, cloudwatch_wrapper):
    clusters = elasticache_client.describe_cache_clusters()['CacheClusters']
    unused_clusters = []

    for cluster in clusters:
        cluster_id = cluster['CacheClusterId']
        status = cluster['CacheClusterStatus']

        if status != 'available':
            unused_clusters.append(cluster_id)
        else:
            connections_metrics = cloudwatch_wrapper.get_metric_statistics(
                namespace='AWS/ElastiCache',
                metric_name='CurrConnections',
                dimensions=[{'Name': 'CacheClusterId', 'Value': cluster_id}],
                start_time=datetime.now(timezone.utc) - timedelta(days=10),
                end_time=datetime.now(timezone.utc),
                period=86400
            )
            avg_connections = sum([point['Average'] for point in connections_metrics]) / len(connections_metrics) if connections_metrics else 0

            if avg_connections == 0:
                unused_clusters.append(cluster_id)

    return unused_clusters

def list_unused_cloudfront_distributions(cloudfront_client):
    distributions = cloudfront_client.list_distributions().get('DistributionList', {}).get('Items', [])
    unused_distributions = []

    for dist in distributions:
        distribution_id = dist['Id']
        domain_name = dist['DomainName']
        enabled = dist['Enabled']

        if not enabled:
            unused_distributions.append({"Id": distribution_id, "DomainName": domain_name, "Reason": "Disabled"})

    return unused_distributions


def build_metric_data_queries(domain_name, region, metric_descriptions):
    queries = []
    relevant_metrics = ['SearchRate', 'IndexingRate']
    for metric in metric_descriptions:
        metric_name = metric['MetricName']
        if metric_name not in relevant_metrics:
            continue
        for stat in ['Average']:
            label = f"{domain_name} {region} {metric_name} {stat}"
            query_id = 'a' + str(uuid.uuid1()).lower().replace('-', '_')
            queries.append({
                'Id': query_id,
                'Label': label,
                'MetricStat': {
                    'Metric': {
                        'Namespace': 'AWS/ES',
                        'MetricName': metric_name,
                        'Dimensions': metric['Dimensions']
                    },
                    'Period': 300,
                    'Stat': stat,
                }
            })
    return queries

def grouper(iterable, n):
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk

def send_slack_message(message):
    webhook_url = os.environ['SLACK_WEBHOOK_URL']
    payload = {
        "text": message
    }
    try:
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        logger.info("Slack message sent successfully.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send Slack message. Error: {e}")
        sys.exit(1)

def generate_html_report(data):
    template_str = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AWS Unused Resources Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
            th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
            th { background-color: #f4f4f4; }
        </style>
    </head>
    <body>
        <h1>AWS Unused Resources Report</h1>
        <h2>Unattached EBS Volumes</h2>
        <table>
            <thead>
                <tr>
                    <th>Volume ID</th>
                    <th>Size (GiB)</th>
                    <th>Name</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {% for volume in data.ebs_volumes %}
                <tr>
                    <td>{{ volume.VolumeId }}</td>
                    <td>{{ volume.Size }}</td>
                    <td>{{ volume.Name }}</td>
                    <td>{{ volume.Description }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Unused Elastic IPs</h2>
        <table>
            <thead>
                <tr>
                    <th>Public IP</th>
                </tr>
            </thead>
            <tbody>
                {% for ip in data.elastic_ips %}
                <tr>
                    <td>{{ ip.PublicIp }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Unassociated ELBs</h2>
        <table>
            <thead>
                <tr>
                    <th>Load Balancer Name</th>
                </tr>
            </thead>
            <tbody>
                {% for elb in data.elbs %}
                <tr>
                    <td>{{ elb.LoadBalancerName }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Idle RDS Instances</h2>
        <table>
            <thead>
                <tr>
                    <th>RDS Instance Identifier</th>
                </tr>
            </thead>
            <tbody>
                {% for instance in data.rds_instances %}
                <tr>
                    <td>{{ instance.DBInstanceIdentifier }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Unused ELBv2 (ALB/NLB)</h2>
        <table>
            <thead>
                <tr>
                    <th>Load Balancer Name</th>
                    <th>Name</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {% for lb in data.elbv2 %}
                <tr>
                    <td>{{ lb.LoadBalancerName }}</td>
                    <td>{{ lb.Name }}</td>
                    <td>{{ lb.Description }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Idle EC2 Instances</h2>
        <table>
            <thead>
                <tr>
                    <th>Instance ID</th>
                    <th>Name</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {% for instance in data.ec2_instances %}
                <tr>
                    <td>{{ instance.InstanceId }}</td>
                    <td>{{ instance.Name }}</td>
                    <td>{{ instance.State }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Unused IAM Roles</h2>
        <table>
            <thead>
                <tr>
                    <th>Role Name</th>
                    <th>Last Used Date</th>
                </tr>
            </thead>
            <tbody>
                {% for role in data.iam_roles %}
                <tr>
                    <td>{{ role.RoleName }}</td>
                    <td>{{ role.LastUsedDate }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Unused Auto Scaling Groups</h2>
        <table>
            <thead>
                <tr>
                    <th>Auto Scaling Group Name</th>
                </tr>
            </thead>
            <tbody>
                {% for group in data.autoscaling_groups %}
                <tr>
                    <td>{{ group }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Lambda Functions with Zero Invocations (last 30 days)</h2>
        <table>
            <thead>
                <tr>
                    <th>Function Name</th>
                </tr>
            </thead>
            <tbody>
                {% for function in data.lambda_functions %}
                <tr>
                    <td>{{ function.FunctionName }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>EBS Snapshots Older Than One Month</h2>
        <table>
            <thead>
                <tr>
                    <th>Snapshot ID</th>
                    <th>Name</th>
                    <th>Start Time</th>
                    <th>AMI ID</th>
                </tr>
            </thead>
            <tbody>
                {% for snap in data.ebs_snapshots %}
                <tr>
                    <td>{{ snap.SnapshotId }}</td>
                    <td>{{ snap.Name }}</td>
                    <td>{{ snap.StartTime }}</td>
                    <td>{{ snap.AmiId }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>AMIs Older Than One Month</h2>
        <table>
            <thead>
                <tr>
                    <th>AMI ID</th>
                    <th>Name</th>
                    <th>Creation Date</th>
                </tr>
            </thead>
            <tbody>
                {% for ami in data.amis %}
                <tr>
                    <td>{{ ami.ImageId }}</td>
                    <td>{{ ami.Name }}</td>
                    <td>{{ ami.CreationDate }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Unused OpenSearch Domains</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain Name</th>
                    <th>Average Search Rate</th>
                    <th>Average Indexing Rate</th>
                </tr>
            </thead>
            <tbody>
                {% for domain in data.opensearch_domains %}
                <tr>
                    <td>{{ domain.DomainName }}</td>
                    <td>{{ domain.AverageSearchRate }}</td>
                    <td>{{ domain.AverageIndexingRate }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Unused ElastiCache Clusters</h2>
        <table>
            <thead>
                <tr>
                    <th>Cache Cluster ID</th>
                </tr>
            </thead>
            <tbody>
                {% for cluster_id in data.elasticache_clusters %}
                <tr>
                    <td>{{ cluster_id }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Unused CloudFront Distributions</h2>
        <table>
            <thead>
                <tr>
                    <th>Distribution ID</th>
                    <th>Domain Name</th>
                    <th>Reason</th>
                </tr>
            </thead>
            <tbody>
                {% for dist in data.cloudfront_distributions %}
                <tr>
                    <td>{{ dist.Id }}</td>
                    <td>{{ dist.DomainName }}</td>
                    <td>{{ dist.Reason }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </body>
    </html>
    """
    template = Template(template_str)
    return template.render(data=data)

def main():
    try:
        (ec2_client, elb_client, elbv2_client, rds_client, cloudwatch_client, iam_client,
        autoscaling_client, lambda_client, opensearch_client, elasticache_client, cloudfront_client, s3_client) = initialize_aws_clients()
        
        cloudwatch_wrapper = CloudWatchWrapper(cloudwatch_client)
        unused_resources = {
            'ebs_volumes': list_unattached_ebs_volumes(ec2_client),
            'elastic_ips': list_unused_elastic_ips(ec2_client),
            'elbs': list_unassociated_elbs(elb_client),
            'rds_instances': list_idle_rds_instances(rds_client, cloudwatch_wrapper),
            'elbv2': list_unused_elbv2(elbv2_client),
            'ec2_instances': list_idle_ec2_instances(ec2_client, cloudwatch_wrapper),
            'iam_roles': list_unused_iam_roles(iam_client),
            'autoscaling_groups': list_unused_autoscaling_groups(autoscaling_client),
            'lambda_functions': list_unused_lambda_functions(lambda_client, cloudwatch_client),
            'ebs_snapshots': list_old_ebs_snapshots(ec2_client),
            'amis': list_old_amis(ec2_client),
            'opensearch_domains': list_unused_opensearch_domains(opensearch_client, cloudwatch_wrapper),
            'elasticache_clusters': list_unused_elasticache_clusters(elasticache_client, cloudwatch_wrapper),
            'cloudfront_distributions': list_unused_cloudfront_distributions(cloudfront_client)
        }

        report_html = generate_html_report(unused_resources)

        # Save the report to S3
        try:
            s3_client.put_object(Bucket=os.environ['S3_BUCKET_NAME'], Key=os.environ['REPORTFILE'], Body=report_html, ContentType='text/html')
            logger.info(f"Upload to S3 bucket {os.environ['S3_BUCKET_NAME']} was successful.")
        except Exception as e:
            logger.error(f"FAILED: AWS unused resource check in {os.environ['ENVAWS']},  Error uploading to S3: {e}")
            send_slack_message(f"FAILED: AWS unused resource check in {os.environ['ENVAWS']}, Error uploading to S3: {e}")
            sys.exit(1)

    except Exception as e:
        logger.exception(f"FAILED: AWS unused resource check in {os.environ['ENVAWS']}, An error occurred: {e}")
        send_slack_message(f"FAILED: AWS unused resource check in {os.environ['ENVAWS']}, An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

