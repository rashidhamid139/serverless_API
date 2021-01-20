import re
import json
import os.path
import tempfile
from time import time
from fqdn import FQDN
from streaming_form_data import StreamingFormDataParser
from streaming_form_data.targets import ValueTarget, FileTarget, NullTarget
from f5loadbalancer.ingress.factory_generator import Ingress
from f5loadbalancer.common.exceptions import CustomException

class validateParams():
    def __init__(self, fqdn=None ):
        self.fqdn   = self.validate_input( fqdn )

    def validate_input(self, value):
        if len( value ) > 255:
            return None
        elif value[:-1] == ".":
            return value[:-1]
        else:
            return value

    def validate_fqdn_using_fqdn_module(self):
        domain_fqdn = FQDN( self.fqdn )
        return domain_fqdn.is_valid

    def is_valid_fqdn(self):
        if self.validate_fqdn_using_fqdn_module():
            return True
        return False

    def validate_username_email(self, user_email):
        if re.search(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", user_email):
            return True
        return False


def parseFromData(body, headers):

    body_bytes = body.encode('utf-8')

    name_key = 'uploaded-file-key-{}.key'.format(int(time()))
    file_path_key = os.path.join(tempfile.gettempdir(), name_key)
    print(file_path_key)

    name_cert = 'uploaded-file-cert-{}.crt'.format(int(time()))
    file_path_cert = os.path.join(tempfile.gettempdir(), name_cert)
    print(file_path_cert)

    parser = StreamingFormDataParser(headers=headers)

    # -- Defining expected objects

    cloud_provider_obj = ValueTarget()
    parser.register('cloud_provider', cloud_provider_obj)

    region_obj = ValueTarget()
    parser.register('region', region_obj)

    environment_obj = ValueTarget()
    parser.register('environment', environment_obj)

    ticket_number_obj = ValueTarget()
    parser.register('ticket_number', ticket_number_obj)

    ssl_terminate_f5_obj = ValueTarget()
    parser.register('ssl_terminate_f5', ssl_terminate_f5_obj)

    fqdn_obj = ValueTarget()
    parser.register('fqdn', fqdn_obj)

    load_balancing_method_obj = ValueTarget()
    parser.register('load_balancing_method', load_balancing_method_obj)

    members_obj = ValueTarget()
    parser.register('members', members_obj)

    f5_ips_obj = ValueTarget()
    parser.register('f5_ips', f5_ips_obj)

    vip_name_obj = ValueTarget()
    parser.register('vip_name', vip_name_obj)

    file_key = FileTarget(file_path_key)
    parser.register('key_file', file_key)

    file_cert = FileTarget(file_path_cert)
    parser.register('cert_file', file_cert)

    #Parameters below are optional
    try:
        tcp_upload_obj = ValueTarget()
        parser.register('tcp_upload', tcp_upload_obj)

        health_monitor_obj = ValueTarget()
        parser.register('health_monitor', health_monitor_obj)

    except Exception as error:
        pass

    # -- Running parser

    parser.data_received(body_bytes)

    # -- Decoding objects values

    parameters_dict = {}

    parameters_dict["cloud_provider"] = cloud_provider_obj.value.decode().lower().strip()
    parameters_dict["region"] = region_obj.value.decode().lower().strip()
    parameters_dict["environment"] = environment_obj.value.decode().lower().strip()
    parameters_dict["ticket_number"] = ticket_number_obj.value.decode().lower().strip()
    parameters_dict["ssl_terminate_f5"] = ssl_terminate_f5_obj.value.decode().lower().strip()
    parameters_dict["load_balancing_method"] = load_balancing_method_obj.value.decode().lower().strip()

    #validate FQDN 
    if validateParams( fqdn_obj.value.decode().lower().strip() ).is_valid_fqdn():
        parameters_dict["fqdn"] = fqdn_obj.value.decode().lower().strip()
    else:
        msg = "Invalid FQDN, Please Provide a proper FQDN Input"
        raise CustomException(msg, code=400)

        
    # tcp_upload is optional
    try:
        parameters_dict["tcp_upload"] = tcp_upload_obj.value.decode().lower().strip()
    except Exception as error:
        parameters_dict["tcp_upload"] = ""

    # health_monitor is optional
    try:
        parameters_dict["health_monitor"] = health_monitor_obj.value.decode().lower().strip()
    except Exception as error:
        parameters_dict["health_monitor"] = ""

    try:
        parameters_dict["members"] = json.loads(members_obj.value.decode())
    except Exception as error:
        msg = "Error parsing members"
        raise CustomException(msg, code=400)

    try:
        parameters_dict["f5_ips"] = f5_ips_obj.value.decode().lower().strip()
    except Exception as error:
        parameters_dict["f5_ips"] = ""
    try:
        if not ((parameters_dict["f5_ips"] == None) or (parameters_dict["f5_ips"] == "")):
            parameters_dict["f5_ips"] = json.loads(parameters_dict["f5_ips"])
    except Exception as error:
        msg = "Error parsing f5_ips. " + str(error)
        raise CustomException(msg, code=400)

    try:
        parameters_dict["vip_name"] = vip_name_obj.value.decode().lower().strip()
    except Exception as error:
        parameters_dict["vip_name"] = ""


    parameters_dict["key_file"] = name_key
    parameters_dict["cert_file"] = name_cert
    parameters_dict["file_path_key"] = file_path_key
    parameters_dict["file_path_cert"] = file_path_cert

    if validateParams().validate_username_email( headers.get("username", "").lower().strip() ):
        parameters_dict["username"] = headers.get("username", "").lower().strip()
    else:
        msg = "Invalid Parameter, Please Provide a proper username email as Input"
        raise CustomException(msg, code=400)
    

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

        client = Ingress(method, body, headers, queryparams, parsedParameters).operation()
        client.run()

        if client.code == 200:
            status = 'SUCCESS'
            message = "INGRESS WAS CREATED SUCCESSFULLY."
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


def main(event, context):
    print("Event: ", event)
    returnBody = {}
    output = {}
    return_message, return_status, code = execute(event)
    returnBody['status'] = return_status
    returnBody['message'] = return_message
    output['isBase64Encoded'] = True
    output['statusCode'] = code
    output['headers'] = {'content-type': 'application/json'}
    output['body'] = json.dumps(returnBody)

    print("OUTPUT MAIN INGRESS")
    print(output)
    return output


if __name__ == '__main__':
    pass
