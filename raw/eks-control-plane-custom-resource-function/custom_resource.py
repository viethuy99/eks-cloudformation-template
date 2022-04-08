import logging
import socket
import re
import boto3
from crhelper import CfnResource
from OpenSSL import SSL
import certifi

logger = logging.getLogger(__name__)
# Initialise the helper, all inputs are optional, this example shows the defaults
helper = CfnResource(json_logging=False, log_level='INFO', boto_level='CRITICAL', sleep_on_delete=120, ssl_verify=None)

try:
    ## Init code goes here
    pass
except Exception as e:
    helper.init_failure(e)

def str2bool(v):
    return v.lower() in ("yes", "true", "True", "1")

def get_eks_arn(cluster_name):
    eks = boto3.client('eks')
    response = eks.describe_cluster(
                name=cluster_name
    )
    return response['cluster']['arn']

def update_eks_vpc_config(event):
    properties = event['ResourceProperties']
    eks = boto3.client('eks')
    public_access = 'False'
    private_access = 'True'
    public_access_cidr = '0.0.0.0/0'

    if 'EndpointPublicAccess' in properties:
        public_access = properties['EndpointPublicAccess']
    if 'EndpointPrivateAccess' in properties:
        private_access = properties['EndpointPrivateAccess']
    if 'PublicAccessCidrs' in properties:
        public_access_cidr = properties['PublicAccessCidrs']

    response = eks.update_cluster_config(
        name=properties['ClusterName'],
        resourcesVpcConfig={
            'endpointPublicAccess': str2bool(public_access),
            'endpointPrivateAccess': str2bool(private_access),
            'publicAccessCidrs': public_access_cidr
        }
    )
    return response['update']['id']

def poll_update_eks(event):
    properties = event['ResourceProperties']
    update_id = event['CrHelperData']['PhysicalResourceId']
    eks = boto3.client('eks')
    response = eks.describe_update(
        name=properties['ClusterName'],
        updateId=update_id
    )
    update_status = response['update']['status']
    if update_status in ('Cancelled', 'Successful'):
        return update_id
    if update_status == 'Failed':
        raise Exception(response['update']['errors'][0]['errorMessage'])
    return None

def update_eks_logging(event):
    eks = boto3.client('eks')
    properties = event['ResourceProperties']
    log_types = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
    log_enabled = 'False'

    if 'ClusterLogging' in properties:
        log_types = properties['ClusterLogging']['Types']
        log_enabled = properties['ClusterLogging']['Enabled']

    response = eks.update_cluster_config(
        name=properties['ClusterName'],
        logging={
            'clusterLogging': [
                {
                    'types': log_types,
                    'enabled': str2bool(log_enabled)
                }
            ]
        }
    )

    return response['update']['id']

def tag_resource(properties):
    eks = boto3.client('eks')
    if 'Tags' not in properties:
        return
    eks_arn = get_eks_arn(properties['ClusterName'])
    tags = {}
    for tag in properties['Tags']:
        tags[tag['Key']] = tag['Value']
    eks.tag_resource(
        resourceArn=eks_arn,
        tags=tags
    )

def update_eks_tagging(event):
    eks = boto3.client('eks')
    properties = event['ResourceProperties']
    response = eks.describe_cluster(
        name=properties['ClusterName']
    )
    old_tags = response['cluster']['tags']
    new_tags = []
    if 'Tags' in properties:
        new_tags = properties['Tags']
    tag_resource(properties)
    untag_keys = []
    for old_tag in old_tags:
        remove = True
        for new_tag in new_tags:
            if old_tag == new_tag['Key']:
                remove = False
                break
        if remove:
            untag_keys.append(old_tag)
    if len(untag_keys) > 0:
        eks.untag_resource(
            resourceArn=get_eks_arn(properties['ClusterName']),
            tagKeys=untag_keys
        )

def get_oidc_thumbprint(event):
    properties = event['ResourceProperties']
    url = properties['Url']
    
    # using regex to parse the hostname
    p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
    m = re.search(p, url)
    hostname = m.group('host')

    port = 443
    
    context = SSL.Context(method=SSL.TLSv1_METHOD)
    context.load_verify_locations(cafile=certifi.where())
    
    conn = SSL.Connection(context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.settimeout(5)
    conn.connect((hostname, port))
    conn.setblocking(1)
    conn.do_handshake()
    conn.set_tlsext_host_name(hostname.encode())
    
    thumbprint = conn.get_peer_cert_chain()[-1].digest("sha1")
    conn.close()
    return thumbprint.decode("utf-8").replace(":", "").lower()

@helper.create
@helper.update
def update_resource(event, _):
    resource_type = event['ResourceType']
    if resource_type == "Custom::UpdateEksVpcConfig":
        return update_eks_vpc_config(event)
    if resource_type == "Custom::UpdateEksLogging":
        return update_eks_logging(event)
    if resource_type == "Custom::UpdateEksTagging":
        return update_eks_tagging(event)
    if resource_type == "Custom::OidcThumbprint":
        return get_oidc_thumbprint(event)
    raise Exception("Invalid resource type: " + resource_type)

@helper.poll_create
@helper.poll_update
def poll_update_resource(event, _):
    resource_type = event['ResourceType']
    if resource_type == "Custom::UpdateEksVpcConfig":
        return poll_update_eks(event)
    if resource_type == "Custom::UpdateEksLogging":
        return poll_update_eks(event)
    if resource_type == "Custom::UpdateEksTagging":
        return True
    if resource_type == "Custom::OidcThumbprint":
        return event['CrHelperData']['PhysicalResourceId']
    raise Exception("Invalid resource type: " + resource_type)

@helper.delete
def delete_resource(event, _):
    resource_type = event['ResourceType']
    if resource_type == "Custom::UpdateEksVpcConfig":
        pass
    elif resource_type == "Custom::UpdateEksLogging":
        pass
    elif resource_type == "Custom::UpdateEksTagging":
        pass
    elif resource_type == "Custom::OidcThumbprint":
        pass
    else:
        raise Exception("Invalid resource type: " + resource_type)

def lambda_handler(event, context):
    logger.info(event)
    helper(event, context)
