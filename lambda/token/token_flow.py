# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from botocore.exceptions import ClientError

import base64
import boto3
import os
import urllib.parse
import requests


"""
Initializing SDK clients to facilitate reuse across executions
"""

DYNAMODB_CLIENT = boto3.client("dynamodb")

SM_CLIENT = boto3.client(
    service_name = "secretsmanager",
    region_name = os.environ.get("AWS_REGION")
)


def validate_request(params: dict) -> bool:
    """
    Helper function to validate request parameters - can be used to drop requests early during runtime.
    """
    validation = False

    if params["client_id"] == os.environ.get("ClientId") and params["client_secret"] == os.environ.get("ClientSecret"):
        validation = True

    return validation


def get_secret(secret_name):

    # Helper function to get secret from Secrets Manager

    try:
        get_secret_value_response = SM_CLIENT.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response['SecretString']

    return secret


def handler(event, context):
    #  All prints left in to observe behaviour in CloudWatch
    print("+++ FULL EVENT DETAILS +++")
    print(event)
    print("#####################")

    # Decode the cognito request and convert to utf-8
    encoded_message = event["body"]
    decoded_message = base64.b64decode(encoded_message)
    decoded_message = decoded_message.decode("utf-8")

    print("+++ DECODED COGNITO REQUEST +++")
    print(decoded_message)

    # Create parameter dictionary from request
    param_list = list(decoded_message.split("&"))
    param_dict = {}
    for item in param_list:
        key, value = item.split("=")
        param_dict[key] = urllib.parse.unquote(value)

    print("+++ DECODED PARAMETER LIST +++")
    print(param_dict)

    if not validate_request(param_dict):
        print("+++ VALIDATION FAILED - CANCELLING +++")
        return { "statusCode": 400 }

    print("+++ VALIDATION SUCCESSFUL - PROCEEDING +++")

    # Defining pkce toggle here because it is required in multiple different parts below
    pkce_toggle = False

    if os.environ.get("Pkce").lower() == "true":
        pkce_toggle = True
        print("+++ USING PKCE +++")

    # Fetching all details from original request and env vars
    config = {}
    config["auth_code"] = param_dict["code"]
    config["client_id"] = param_dict["client_id"]
    config["client_secret"] = param_dict["client_secret"]
    config["idp_issuer_url"] = os.environ.get("IdpIssuerUrl")
    config["idp_token_url"] = os.environ.get("IdpTokenUrl")
    config["original_response_uri"] = os.environ.get("ResponseUri")

    if pkce_toggle:
        config["code_table"] = os.environ.get("DynamoDbCodeTable")

    print("+++ CONFIGURATION ITEMS +++")
    print(config)

    # Get code_verifier associated with auth_token when using PKCE
    if pkce_toggle:
        code_result = DYNAMODB_CLIENT.get_item(
            TableName = config["code_table"],
            Key = {
                "auth_code": {
                    "S": config["auth_code"]
                }
            }
        )
        code_verifier = code_result["Item"]["code_verifier"]["S"]

        print("+++ CODE VERIFIER FOUND +++")
        print(code_verifier)

   

    # Add client_assertion to the query string params
    param_dict["grant_type"] = "authorization_code"
    param_dict["redirect_uri"] = config["original_response_uri"]

    # Add the api gw url from the authorize request and code verifier when using PKCE
    if pkce_toggle:
        param_dict["code_verifier"] = code_verifier


    # Make the token request
    payload = urllib.parse.urlencode(param_dict)
    print("+++ PAYLOAD +++")
    print(payload)

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(
        url=config["idp_token_url"],
        data=payload,
        headers=headers,
    )

    print("+++ IDP RESPONSE +++")
    print(f"Status: {response.status_code}, Reason: {response.reason}")

    # Return IdP response to Cognito
    data = response.content.decode('utf-8')

    print(data)

    return data

