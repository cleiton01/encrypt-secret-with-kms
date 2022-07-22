import json
import boto3
import base64
from botocore.exceptions import ClientError

import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy


def get_secret():
    print("start execution get_secret")
    
    secret_name = "ARN_SECRET"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    print("client created")
    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        print("ready to get value fromt secret manager")
        
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
        
        
        print("get secret with success fromt secret manager")

    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return get_secret_value_response['SecretString']
            
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return base64.b64decode(get_secret_value_response['SecretBinary'])     
    

def cycle_string(key_arn, source_plaintext, botocore_session=None):
    print("start a new encrypt")
    
    """Encrypts and then decrypts a string under an &KMS; key.

    :param str key_arn: Amazon Resource Name (ARN) of the &KMS; key
    :param bytes source_plaintext: Data to encrypt
    :param botocore_session: existing botocore session instance
    :type botocore_session: botocore.session.Session
    """
    # Set up an encryption client with an explicit commitment policy. If you do not explicitly choose a
    # commitment policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT is used by default.
    print("====== 1")
    client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)

    # Create an AWS KMS master key provider
    kms_kwargs = dict(key_ids=[key_arn])
    print("====== 2")
    if botocore_session is not None:
        kms_kwargs["botocore_session"] = botocore_session
    master_key_provider = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**kms_kwargs)
    
    print("====== 3")
    # Encrypt the plaintext source data
    ciphertext, encryptor_header = client.encrypt(source=source_plaintext, key_provider=master_key_provider)
    print("====== 4")
    # Decrypt the ciphertext
    cycled_plaintext, decrypted_header = client.decrypt(source=ciphertext, key_provider=master_key_provider)
    print("====== 5")
    # Verify that the "cycled" (encrypted, then decrypted) plaintext is identical to the source plaintext
    assert cycled_plaintext == source_plaintext
    print("====== 6")
    # Verify that the encryption context used in the decrypt operation includes all key pairs from
    # the encrypt operation. (The SDK can add pairs, so don't require an exact match.)
    #
    # In production, always use a meaningful encryption context. In this sample, we omit the
    # encryption context (no key pairs).
    assert all(
        pair in decrypted_header.encryption_context.items() for pair in encryptor_header.encryption_context.items()
    )
    print("====== 7")


def lambda_handler(event, context):
    # TODO implement
    arn=""
    
    body = event["body"]
    
    json_acceptable_string = body.replace("'", "\"").replace("{","{\"").replace(":",'":' )
    d = json.loads(json_acceptable_string)
    password_text = d["password"]
    
    print(d["password"])
    
    cycle_string(arn,password_text )
    
    
    print(get_secret())
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
