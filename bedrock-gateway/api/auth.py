import json
import os
from typing import Annotated

import boto3
from botocore.exceptions import ClientError
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from api.setting import DEFAULT_API_KEYS

api_key_param = os.environ.get("API_KEY_PARAM_NAME")
api_key_secret_arn = os.environ.get("API_KEY_SECRET_ARN")
api_key_env = os.environ.get("API_KEY")
AWS_REGION = os.environ.get("AWS_REGION")

api_key = None

if api_key_param:
    # For backward compatibility.
    # Please now use secrets manager instead.
    try:
        ssm = boto3.client("ssm", AWS_REGION)
        api_key = ssm.get_parameter(Name=api_key_param, WithDecryption=True)["Parameter"]["Value"]
    except ClientError as e:
        raise RuntimeError(f"Unable to retrieve API KEY from SSM parameter '{api_key_param}': {e}")
elif api_key_secret_arn:
    try:
        sm = boto3.client("secretsmanager", AWS_REGION)
        response = sm.get_secret_value(SecretId=api_key_secret_arn)
        if "SecretString" in response:
            secret = json.loads(response["SecretString"])
            api_key = secret["api_key"]
    except ClientError as e:
        raise RuntimeError(f"Unable to retrieve API KEY from Secrets Manager: {e}")
    except KeyError:
        raise RuntimeError('Please ensure the secret contains a "api_key" field')
elif api_key_env:
    api_key = api_key_env
else:
    # For local use only.
    api_key = DEFAULT_API_KEYS

if not api_key:
    raise RuntimeError("No API key could be retrieved from any configured source")

security = HTTPBearer()


def api_key_auth(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
):
    if credentials.credentials != api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")