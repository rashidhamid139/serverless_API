import re
import json
import os.path
from netaddr import IPNetwork, IPAddress


def check_ip_in_cidr(ip_address, cidr_block):
    flag = False
    message = "Invalid Params"
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
    if (re.search(regex, ip_address) ):
        pass
    else:
        message = "Not Valid IP Address"
        return message, flag
    try:
        value = IPAddress(ip_address) in IPNetwork(cidr_block)
        if value:
            flag = True
            message = "SUCCESS"
        else:
            flag = False
            message = "Not in CIDR"
    except Exception as e:
        flag = False
        message = "Invalid cidr_block"
    return message, flag

def validate_inputs(event_object):
    input_params = event_object.get('queryStringParameters')
    if 'ip_address' in input_params and input_params['ip_address'].strip() != '':
        ip_address = input_params['ip_address'].strip()
    else:
        return None, "ip_address parameter missing"
    if 'cidr_block' in input_params and input_params['cidr_block'].strip() != '':
        cidr_block = input_params['cidr_block'].strip()
    else:
        return None, "cidr_block parameter missing"
    return ip_address, cidr_block


def main(event, context):

    try:
        method = event.get('httpMethod', "")
        if method == "GET":
            if (validate_inputs(event)[0] ):
                ip_address, cidr_block = validate_inputs(event)
                _, flag = check_ip_in_cidr(ip_address, cidr_block)
                output = {
                    'status': 'SUCCESS',
                    'flag': flag
                }
                return {
                    'headers': {'content-type': 'application/json'},
                    'statusCode': 200,
                    'body' : json.dumps(output)
                }
            else:
                output = {
                    'status': 'ERROR',
                    'message': 'Please Provide required Parameters: ' + validate_inputs(event)[1]
                }
                return {
                    'headers': {'content-type': 'application/json'},
                    'statusCode': 300,
                    'body': json.dumps(output)
                }
        else:
            output = {
                'status': "ERROR",
                'message': "Invalid HTTP method",
                'flag': False
            }
            return {
                'headers': {'content-type': 'application/json'},
                'statusCode': 405,
                'body': json.dumps(output)
            }

    except Exception as e:
        output = {
                'status': 'ERROR',
                'message': 'Exception on validating the IP.'
            }
        return {
            'headers': {'content-type': 'application/json'},
            'statusCode': 500,
            'body': json.dumps(output)
            }



if __name__ == '__main__':
    pass