import json
import os.path
import tempfile
from time import time
from streaming_form_data import StreamingFormDataParser
from streaming_form_data.targets import ValueTarget, FileTarget, NullTarget
from f5loadbalancer.irules.factory_generator import IRules
from f5loadbalancer.common.exceptions import CustomException


def parseFromData(body, headers):

    parameters_dict = {}

    parameters_dict["cloud_provider"] = body.get("cloud_provider", "").lower()
    parameters_dict["region"] = body.get("region", "").lower()
    parameters_dict["environment"] = body.get("environment", "").lower()
    parameters_dict["tcp_upload"] = body.get("tcp_upload", "").lower()
    parameters_dict["fqdn"] = body.get("fqdn", "").lower()
    parameters_dict["pool_name"] = body.get("pool_name", "").lower()
    parameters_dict["f5_ips"] = body.get("f5_ips", "").lower()
    parameters_dict["vip_name"] = body.get("vip_name", "").lower()

    parameters_dict["username"] = headers.get("username", "").lower()

    print(parameters_dict)

    return parameters_dict


def execute(event):

    try:

        try:
            body = event.get('body', {})
            headers = event.get('headers', {})
            method = event.get('httpMethod', "")
            queryparams = event.get('queryStringParameters', {})

            parsedParameters = parseFromData(body, headers)
            parsedParameters = json.dumps(parsedParameters)
        except Exception as error:
            status = 'ERROR'
            message = "Invalid or missing user input. " + str(error)
            code = 400
            return(message, status, code)

        client = IRules(method, body, headers, queryparams,
                        parsedParameters).operation()
        client.run()

        if client.code == 200:
            status = 'SUCCESS'
            message = "IRULE WAS CREATED SUCCESSFULLY."
            code = client.code
        elif client.code == 400:
            status = 'ERROR'
            message = "Invalid or missing user input. " + str(client.message)
            code = client.code
        elif client.code == 401:
            status = 'ERROR'
            message = "Unauthorized to perform this call. " +  str(client.message)
            code = client.code
        elif client.code == 405:
            status = 'ERROR'
            message = "Method not allowed this resource. " +  str(client.message)
            code = client.code
        elif client.code == 409:
            status = 'ERROR'
            message = "Resource already exists. " +  str(client.message)
            code = client.code
        else:
            status = 'ERROR'
            message = "Internal Server Error. " +  str(client.message)
            code = 500

    except KeyError as error:
        status = 'ERROR'
        message = "Invalid or missing user input. " + str(error)
        code = 400
    except CustomException as error:
        if error.code == 400:
            status = 'ERROR'
            message = "Invalid or missing user input. " + str(error.message)
            code = error.code
        elif error.code == 401:
            status = 'ERROR'
            message = "Unauthorized to perform this call. " +  str(error.message)
            code = error.code
        elif error.code == 405:
            status = 'ERROR'
            message = "Method not allowed this resource. " +  str(error.message)
            code = error.code
        elif error.code == 409:
            status = 'ERROR'
            message = "Resource already exists. " +  str(error.message)
            code = error.code
        else:
            status = 'ERROR'
            message = "Internal Server Error. " +  str(error.message)
            code = 500
    except Exception as error:
        status = 'ERROR'
        message = "Internal Server Error. " + str(error)
        code = 500

    return(message, status, code)


def mainIRule(event):

    print("ON mainIrule")

    returnBody = {}
    output = {}
    return_message, return_status, code = execute(event)
    returnBody['status'] = return_status
    returnBody['message'] = return_message
    output['isBase64Encoded'] = True
    output['statusCode'] = code
    output['headers'] = {'content-type': 'application/json'}
    output['body'] = json.dumps(returnBody)

    print("OUTPUT mainIrule")
    print(output)

    return output


if __name__ == "__main__":
    pass
