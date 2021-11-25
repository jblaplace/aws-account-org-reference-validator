import boto3
import json
import botocore
from botocore.config import Config

"""
This scripts validates identify resource policies in the account that reference the PrincipalOrg attribute.
Policies that do reference that attribute will be broken once the account moves under a new organization:

Ref: "If you use the aws:PrincipalOrgID condition key in your resource-based policies to restrict access only 
to the principals from AWS accounts in your Organization, 
then you must change these policies before moving the member account to another Organization."

https://aws.amazon.com/premiumsupport/knowledge-center/organizations-move-accounts/

The list of services was gathered from https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html

Author: Jean-Baptiste Laplace
"""

KEY_WORD = "PrincipalOrg"
REGIONS = ['ca-central-1', 'us-east-1']
CODE_ARTIFACT_UNSUPPORTED_REGIONS = ['ca-central-1']


def IAMCustomerManagedValidator():
    print('Validation IAM customer managed Policies')
    client = boto3.client('iam')
    policies_paginator = client.get_paginator('list_policies')
    count = 0
    for policies in policies_paginator.paginate(Scope='Local'):
        for policy in policies['Policies']:
            count = count+1
            print('\tValidation %i' % (count))
            policyDoc = client.get_policy(PolicyArn=policy['Arn'])
            policyVersion = client.get_policy_version(
                PolicyArn=policy['Arn'], VersionId=policyDoc['Policy']['DefaultVersionId'])
            if KEY_WORD in json.dumps(policyVersion['PolicyVersion']['Document']['Statement']):
                print(policyDoc)


def IAMRoleValidator():
    print('Validation IAM Roles inline Policies')
    client = boto3.client('iam')
    role_paginator = client.get_paginator('list_roles')
    count = 0
    for roles in role_paginator.paginate():
        for role in roles['Roles']:
            count = count + 1
            print('\tValidation %i' % (count))
            try:
                rolePolicies = client.list_role_policies(
                    RoleName=role['RoleName'])
                policyNames = rolePolicies['PolicyNames']
            except botocore.exceptions.ClientError as exception:
                print('\tError',
                      policyName, exception)
                continue

            if 'AssumeRolePolicyDocument' in role.keys():
                if KEY_WORD in json.dumps(role['AssumeRolePolicyDocument']):
                    print(role['RoleName'])
                    print(role['AssumeRolePolicyDocument'])

            for policyName in policyNames:
                policy = client.get_role_policy(
                    RoleName=role['RoleName'], PolicyName=policyName)

                if KEY_WORD in json.dumps(policy['PolicyDocument']):
                    print(role['RoleName'])
                    print(policy['PolicyDocument'])


def S3Validator():
    print('Validation S3 Resource Policy')
    client = boto3.client('s3')
    buckets = client.list_buckets()
    count = 0
    for bucket in buckets["Buckets"]:
        count = count + 1
        print('\tValidation %i' % (count))
        try:
            bucket_policy = client.get_bucket_policy(Bucket=bucket["Name"])
            policy = bucket_policy["Policy"]
            if KEY_WORD in policy:
                print("\t", bucket["Name"], ":->", policy)
        except:
            print("\tNo bucket policy")


def S3GlacierValidator():
    for region in REGIONS:
        config = Config(region_name=region)
        client = boto3.client('glacier', config=config)
        print('Validation S3 Glacier', region, 'Resource Policy')
        paginator = client.get_paginator('list_vaults')

        count = 0
        for page in paginator.paginate():

            for vault in page['VaultList']:
                count = count + 1
                print('\tValidation %i' % (count))
                try:
                    response = client.get_vault_access_policy(
                        vaultName=vault['VaultName'])
                    policy = response['policy']['Policy']

                    if KEY_WORD in policy:
                        print('\t', vault['VaultName'])
                        print('\t', policy)
                except:
                    print('\tNo resource policy')


def LambdaValidator():
    for region in REGIONS:
        config = Config(region_name=region)
        client = boto3.client('lambda', config=config)
        print('Validation Lambda', region, 'Resource Policy')
        paginator = client.get_paginator('list_functions')

        count = 0
        for lambdaPage in paginator.paginate():
            for awsLambda in lambdaPage['Functions']:
                count = count + 1
                print('\tValidation %i' % (count))
                try:
                    response = client.get_policy(
                        FunctionName=awsLambda['FunctionName'])
                    policy = response['Policy']
                    if KEY_WORD in policy:
                        print('\t', awsLambda['FunctionName'],
                              awsLambda['Version'])
                        print('\t', policy)
                except:
                    print('\tNo resource policy')


def ECRValidator():
    for region in REGIONS:
        config = Config(region_name=region)
        client = boto3.client('ecr', config=config)
        print('Validation ECR', region, 'Resource Policy')
        paginator = client.get_paginator('describe_repositories')

        count = 0
        for page in paginator.paginate():
            for item in page['repositories']:
                count = count + 1
                print('\tValidation %i' % (count))

                try:
                    response = client.get_repository_policy(
                        registryId=item['registryId'], repositoryName=item['repositoryName'])
                    policy = response['policyText']
                    if KEY_WORD in policy:
                        print('\tECR:', item['repositoryName'])
                        print('\tPolicy:', policy)
                except client.exceptions.ResourceNotFoundException:
                    continue
                except Exception as exception:
                    print('\tError', exception)


def BackupVaultRegionalValidator(count, region, nextToken=None):
    config = Config(region_name=region)
    client = boto3.client('backup', config=config)

    if nextToken != None:
        vaultsResponse = client.list_backup_vaults(NextToken=nextToken)
    else:
        vaultsResponse = client.list_backup_vaults()

    vaults = vaultsResponse['BackupVaultList']

    for vault in vaults:
        count = count + 1
        print('\tValidation %i' % (count))
        policy = client.get_backup_vault_access_policy(
            BackupVaultName=vault['BackupVaultName']
        )

        if KEY_WORD in policy['Policy']:
            print('\tVault:', vault['BackupVaultName'])
            print(policy['Policy'])

    nextToken = None
    if 'NextToken' in vaultsResponse.keys():
        nextToken = vaultsResponse['NextToken']
    if nextToken != None:
        return BackupVaultValidator(count, nextToken, region)


def BackupVaultValidator():
    for region in REGIONS:
        print('Validation Backup Vault', region, 'Resource Policy')
        BackupVaultRegionalValidator(0, region)


def EFSRegionalValidator(count, region, nextToken=None):
    config = Config(region_name=region)
    client = boto3.client('efs', config=config)

    if nextToken != None:
        fileSystemsResponse = client.describe_file_systems(Marker=nextToken)
    else:
        fileSystemsResponse = client.describe_file_systems()

    fileSystems = fileSystemsResponse['FileSystems']

    for fileSystem in fileSystems:
        count = count + 1
        print('\tValidation %i' % (count))
        try:
            policy = client.describe_file_system_policy(
                FileSystemId=fileSystem['FileSystemId']
            )

            if KEY_WORD in policy['Policy']:
                print('\tfileSystem:',
                      fileSystem['Name'], fileSystem['FileSystemId'])
                print(policy['Policy'])
        except client.exceptions.PolicyNotFound as pnf:
            continue

    nextToken = None
    if 'Marker' in fileSystemsResponse.keys():
        nextToken = fileSystemsResponse['Marker']
    if nextToken != None:
        return EFSRegionalValidator(count, nextToken, region)


def EFSValidator():
    for region in REGIONS:
        print('Validation EFS', region, 'Resource Policy')
        EFSRegionalValidator(0, region)


def CodeArtifactDomainValidator():
    for region in REGIONS:
        if region not in CODE_ARTIFACT_UNSUPPORTED_REGIONS:
            config = Config(region_name=region)
            client = boto3.client('codeartifact', config=config)
            print('Validation CodeArtifact Domains', region, 'Resource Policy')
            paginator = client.get_paginator('list_domains')

            count = 0
            for page in paginator.paginate():

                for item in page['domains']:
                    count = count + 1
                    print('\tValidation %i' % (count))

                    try:
                        response = client.get_domain_permissions_policy(
                            domain=item['name'],
                            domainOwner=item['owner'])
                        policy = response['policy']

                        if KEY_WORD in policy['document']:
                            print('\tDomain:', item['name'])
                            print('\tPolicy:', policy['document'])
                    except client.exceptions.ResourceNotFoundException:
                        continue
                    except Exception as exception:
                        print('\tError', exception)


def CodeArtifactRepositoryValidator():
    for region in REGIONS:
        if region not in CODE_ARTIFACT_UNSUPPORTED_REGIONS:
            config = Config(region_name=region)
            client = boto3.client('codeartifact', config=config)
            print('Validation CodeArtifact Repositories',
                  region, 'Resource Policy')
            paginator = client.get_paginator('list_repositories')

            count = 0
            for page in paginator.paginate():
                for item in page['repositories']:
                    count = count + 1
                    print('\tValidation %i' % (count))
                    try:
                        response = client.get_repository_permissions_policy(
                            domain=item['domainName'],
                            domainOwner=item['domainOwner'],
                            repository=item['name'])
                        policy = response['policy']

                        if KEY_WORD in policy['document']:
                            print('\tRepository:', item['name'])
                            print('\tPolicy:', policy['document'])
                    except client.exceptions.ResourceNotFoundException:
                        continue
                    except Exception as exception:
                        print('\tError', exception)


def SecretsManagerValidator():
    for region in REGIONS:
        config = Config(region_name=region)
        client = boto3.client('secretsmanager', config=config)
        print('Validation SecretsManager Domains',
              region, 'Resource Policy')
        paginator = client.get_paginator('list_secrets')

        count = 0
        for page in paginator.paginate():
            for item in page['SecretList']:
                count = count + 1
                print('\tValidation %i' % (count))
                try:
                    response = client.get_resource_policy(
                        SecretId=item['ARN']
                    )
                    if 'ResourcePolicy' in response.keys():
                        policy = response['ResourcePolicy']

                        if KEY_WORD in policy:
                            print('\tSecret:', item['Name'])
                            print('\tPolicy:', policy)
                except client.exceptions.ResourceNotFoundException:
                    continue
                except Exception as exception:
                    print('\tError', exception)


def Cloud9Validator():
    print('Cloud9Validator() TODO')


def CodeBuildValidator():
    print('CodeBuildValidator() TODO')


def AcmePrivateValidator():
    print('AcmePrivateValidator() TODO')


def KMSValidator():
    for region in REGIONS:
        config = Config(region_name=region)
        client = boto3.client('kms', config=config)
        print('Validation KMS',
              region, 'Resource Policy')
        paginator = client.get_paginator('list_keys')

        count = 0
        for page in paginator.paginate():
            for item in page['Keys']:
                count = count + 1
                print('\tValidation %i' % (count))
                try:
                    response = client.get_key_policy(
                        KeyId=item['KeyArn'],
                        PolicyName='default'
                    )

                    if 'Policy' in response.keys():
                        policy = response['Policy']

                        if KEY_WORD in policy:
                            print('\tSecret:', item['KeyArn'])
                            print('\tPolicy:', policy)
                except botocore.exceptions.ClientError as exception:
                    print('\tError',
                          item['KeyArn'], exception)
                except Exception as exception:
                    print('\tError', exception)


def LexV2Validator():
    print('LexV2Validator() TODO')


def CloudWatchLogsValidator():
    for region in REGIONS:
        config = Config(region_name=region)
        client = boto3.client('logs', config=config)
        print('Validation Logs',
              region, 'Resource Policy')
        try:
            paginator = client.get_paginator('describe_resource_policies')
            count = 0
            for page in paginator.paginate():
                for item in page['resourcePolicies']:
                    count = count + 1
                    print('\tValidation %i' % (count))

                    if 'policyDocument' in item.keys():
                        policy = item['policyDocument']

                        if KEY_WORD in policy:
                            print('\tPolicy:', item['policyName'])
                            print('\tPolicy Doc:', policy)

        except botocore.exceptions.ClientError as exception:
            print('\tError', exception)
            continue


def CloudWatchLogsDestinationValidator():
    for region in REGIONS:
        config = Config(region_name=region)
        client = boto3.client('logs', config=config)
        print('Validation Logs Destination',
              region, 'Resource Policy')
        try:
            paginator = client.get_paginator('describe_destinations')
            count = 0
            for page in paginator.paginate():
                for item in page['destinations']:
                    count = count + 1
                    print('\tValidation %i' % (count))

                    if 'accessPolicy' in item.keys():
                        policy = item['accessPolicy']

                        if KEY_WORD in policy:
                            print('\tPolicy:', item['destinationName'])
                            print('\tPolicy Doc:', policy)

        except botocore.exceptions.ClientError as exception:
            print('\tError', exception)
            continue


IAMRoleValidator()
IAMCustomerManagedValidator()
S3Validator()
S3GlacierValidator()
LambdaValidator()
ECRValidator()
BackupVaultValidator()
EFSValidator()
CodeArtifactDomainValidator()
CodeArtifactRepositoryValidator()
Cloud9Validator()
CodeBuildValidator()
SecretsManagerValidator()
AcmePrivateValidator()
KMSValidator()
LexV2Validator()
CloudWatchLogsValidator()
CloudWatchLogsDestinationValidator()
