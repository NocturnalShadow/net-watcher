import os
import boto3

ec2 = boto3.client('ec2')

def handler(event, context):
    instance_id = os.environ['INSTANCE_ID']
    action = os.environ.get('ACTION', 'stop')
    
    if action == 'start':
        ec2.start_instances(InstanceIds=[instance_id])
        print(f'Started instance: {instance_id}')
    else:
        ec2.stop_instances(InstanceIds=[instance_id])
        print(f'Stopped instance: {instance_id}')
    
    return {
        'statusCode': 200,
        'body': f'Instance {instance_id} {action} completed'
    }