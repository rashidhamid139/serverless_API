import os
import json
import uuid
import boto3
import requests

from datetime import datetime
from .exceptions import CustomException


url = "https://authz.azurewebsites.net/security/resourceaccessmanagement/v1/"


### DYNAMODB

def connect_dynamodb():
    AUTHZ_TABLE = os.environ['DYNAMO_TABLE_AUTHZ']
    dyndb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dyndb.Table(AUTHZ_TABLE)
    return table

def put_authz_item_dynamodb(resource_id, authorization_id):
    try:
        print("On put_authz_item_dynamodb")
        table = connect_dynamodb()

        response = table.put_item(
            Item={
                'ResourceID': resource_id,
                'AuthID': authorization_id
            }
        )
        return response['ResponseMetadata']['HTTPStatusCode']
    except Exception as error:
        raise CustomException("Authorization record was not sucessfully created on DynamoDB", code=500)

def delete_authz_item_dynamodb(resource_id):
    try:
        print("On delete_authz_item_dynamodb")
        print(resource_id)
        table = connect_dynamodb()

        table.delete_item(
            Key={
                'ResourceID': resource_id
            }
        )

    except Exception as error:
        print("Authorization record was not sucessfully deleted on DynamoDB")
        print(error)
        pass


### CREATE AUTHZ

def create_role(user_name):
    user_id = user_name.split('@')[0]
    role_id = None

    if role_id is None:
        role_id = str(uuid.uuid4())
        payload = {"id": role_id,
                   "roleName": user_id,
                   "createDate": str(datetime.utcnow().isoformat())+'Z',
                   "identities": {
                       "users": [
                           user_name
                       ],
                       "groups": []
                   }
                   }

        headers = {"content-type": "application/json"}
        response = requests.request("POST", url + "roles",
                                    headers=headers, data=json.dumps(payload), verify=False)
        if response.status_code == 201:
            return role_id
        else:
            return None
    else:
        return None


def create_authorization(resource_id, role_id,
                         policy_id='1b085fa1-17ae-47e2-93d7-37804af10e09'):
    if role_id is not None:
        authorization_id = str(uuid.uuid4())
        payload = {
            "id": authorization_id,
            "resourceId": resource_id,
            "roleId": role_id,
            "policyId": policy_id
        }

        headers = {
            'Content-Type': 'application/json'
        }
        response = requests.request("POST", url + "authorizations",
                                    headers=headers,
                                    data=json.dumps(payload), verify=False)
        if response.status_code == 201:
            return authorization_id
        else:
            return None
    else:
        return None


# CREATE AUTHZ - MAIN
def create_authz(user_name, resource_id):
    try:
        print("In create_authz")
        roleId = create_role(user_name)
        if roleId is None:
            raise CustomException("Role ID not created", code=500)
        authorization_id = create_authorization(resource_id, roleId)
        if authorization_id is None:
            raise CustomException("Authorization ID not created", code=500)

        flag_response = put_authz_item_dynamodb(resource_id, authorization_id)

        if flag_response == 200:
            print("Authorization record created on DynamoDB")
            pass
        else:
            delete_authz(user_name, resource_id)
            msg = "AuthZ was not created."
            raise CustomException(msg, code=500)

    except CustomException as error:
        raise CustomException(error.message, code=error.code)
    except Exception as error:
        msg = "AuthZ was not created."
        raise CustomException(msg, code=500)


### DELETE AUTHZ

def get_authorization(user_name, resource_id):

    validate_url = url + "authorizations/validate"
    query = {
        "resourceId": resource_id,
        "userId": user_name,
        "action": "Delete"
    }
    response = requests.get(validate_url, params=query, verify=False)
    return(response.json()["id"])

# DELETE AUTHZ - MAIN
def delete_authz(user_name, resource_id):
    try:
        print("In delete_authz")
        print(resource_id)
        authorization_id = get_authorization(user_name, resource_id)
        delete_url = url + "authorizations/" + authorization_id
        response = requests.request("DELETE", delete_url, verify=False)
        if response.status_code == 200:
            delete_authz_item_dynamodb(resource_id)
    except Exception as error:
        print("Error deleting AuthZ authorization")
        print(error)
        pass