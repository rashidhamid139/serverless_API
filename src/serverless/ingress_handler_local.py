import json
import os.path
import tempfile
from time import time
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

    # def validate_fqdn_with_regex(self):
    #     allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    #     return all(allowed.match(x) for x in self.fqdn.split("."))
        
    def validate_fqdn_using_fqdn_module(self):
        domain_fqdn = FQDN( self.fqdn )
        return domain_fqdn.is_valid

    def is_valid_fqdn(self):
        if self.validate_fqdn_using_fqdn_module():
            return True
        return False

    def validate_username_email(self, user_email):
        email = input("enter the mail address::")
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
    if validateParams( '' ).is_valid_fqdn():
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

        client = Ingress(method, body, headers, queryparams,
                         parsedParameters).operation()
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


def main():

    event = '{"resource": "/ingress", "path": "/ingress", "httpMethod": "POST", "headers": {"Accept": "*/*", "Accept-Encoding": "gzip, deflate, br", "Cache-Control": "no-cache", "CloudFront-Forwarded-Proto": "https", "CloudFront-Is-Desktop-Viewer": "true", "CloudFront-Is-Mobile-Viewer": "false", "CloudFront-Is-SmartTV-Viewer": "false", "CloudFront-Is-Tablet-Viewer": "false", "CloudFront-Viewer-Country": "US", "content-type": "multipart/form-data; boundary=--------------------------381636933030506020173192", "Host": "0cejeiswsk.execute-api.us-east-1.amazonaws.com", "Postman-Token": "5b0d4893-1b27-442d-bb2c-cd29ef6211d6", "User-Agent": "PostmanRuntime/7.26.5", "Via": "1.1 1e357724bdb0ea3eaba680124ea9eacb.cloudfront.net (CloudFront)", "X-Amz-Cf-Id": "1y6rVskT46SmMkh1fU7PvDm_zy5FyPoFQm-ouV2DzBtB5uBFfhWMnA==", "X-Amzn-Trace-Id": "Root=1-5f97872e-094f49eb218f5d873d5b12d5", "x-api-key": "n6GgdSSeCb29uqQUZZiPy5j3dK5ZkCFnaxLSVevp", "X-Forwarded-For": "24.30.108.230, 64.252.176.69", "X-Forwarded-Port": "443", "X-Forwarded-Proto": "https"}, "multiValueHeaders": {"Accept": ["*/*"], "Accept-Encoding": ["gzip, deflate, br"], "Cache-Control": ["no-cache"], "CloudFront-Forwarded-Proto": ["https"], "CloudFront-Is-Desktop-Viewer": ["true"], "CloudFront-Is-Mobile-Viewer": ["false"], "CloudFront-Is-SmartTV-Viewer": ["false"], "CloudFront-Is-Tablet-Viewer": ["false"], "CloudFront-Viewer-Country": ["US"], "content-type": ["multipart/form-data; boundary=--------------------------381636933030506020173192"], "Host": ["0cejeiswsk.execute-api.us-east-1.amazonaws.com"], "Postman-Token": ["5b0d4893-1b27-442d-bb2c-cd29ef6211d6"], "User-Agent": ["PostmanRuntime/7.26.5"], "Via": ["1.1 1e357724bdb0ea3eaba680124ea9eacb.cloudfront.net (CloudFront)"], "X-Amz-Cf-Id": ["1y6rVskT46SmMkh1fU7PvDm_zy5FyPoFQm-ouV2DzBtB5uBFfhWMnA=="], "X-Amzn-Trace-Id": ["Root=1-5f97872e-094f49eb218f5d873d5b12d5"], "x-api-key": ["n6GgdSSeCb29uqQUZZiPy5j3dK5ZkCFnaxLSVevp"], "X-Forwarded-For": ["24.30.108.230, 64.252.176.69"], "X-Forwarded-Port": ["443"], "X-Forwarded-Proto": ["https"]}, "queryStringParameters": null, "multiValueQueryStringParameters": null, "pathParameters": null, "stageVariables": null, "requestContext": {"resourceId": "aadsy8", "resourcePath": "/ingress", "httpMethod": "POST", "extendedRequestId": "VDIPQHRsIAMFxAA=", "requestTime": "27/Oct/2020:02:34:22 +0000", "path": "/dev/ingress", "accountId": "890882436612", "protocol": "HTTP/1.1", "stage": "dev", "domainPrefix": "0cejeiswsk", "requestTimeEpoch": 1603766062328, "requestId": "80cf188a-eed3-4fd3-b5ab-dd80e8247f56", "identity": {"cognitoIdentityPoolId": null, "cognitoIdentityId": null, "apiKey": "n6GgdSSeCb29uqQUZZiPy5j3dK5ZkCFnaxLSVevp", "principalOrgId": null, "cognitoAuthenticationType": null, "userArn": null, "apiKeyId": "bcq4d1c3kd", "userAgent": "PostmanRuntime/7.26.5", "accountId": null, "caller": null, "sourceIp": "24.30.108.230", "accessKey": null, "cognitoAuthenticationProvider": null, "user": null}, "domainName": "0cejeiswsk.execute-api.us-east-1.amazonaws.com", "apiId": "0cejeiswsk"}, "isBase64Encoded": false}'
    body = "----------------------------381636933030506020173192\r\nContent-Disposition: form-data; name=\"key_file\"; filename=\"alice.key\"\r\nContent-Type: application/octet-stream\r\n\r\n-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data; name=\"cert_file\"; filename=\"alice.crt\"\r\nContent-Type: application/x-x509-ca-cert\r\n\r\nCertificate:\n    Data:\n        Version: 3 (0x2)\n        Serial Number: 1 (0x1)\n        Signature Algorithm: sha1WithRSAEncryption\n        Issuer: C=FR, ST=Alsace, L=Strasbourg, O=www.freelan.org, OU=freelan, CN=Freelan Sample Certificate Authority/emailAddress=contact@freelan.org\n        Validity\n            Not Before: Apr 27 10:31:18 2012 GMT\n            Not After : Apr 25 10:31:18 2022 GMT\n        Subject: C=FR, ST=Alsace, O=www.freelan.org, OU=freelan, CN=alice/emailAddress=contact@freelan.org\n        Subject Public Key Info:\n            Public Key Algorithm: rsaEncryption\n                Public-Key: (4096 bit)\n                Modulus:\n                    00:dd:6d:bd:f8:80:fa:d7:de:1b:1f:a7:a3:2e:b2:\n                    02:e2:16:f6:52:0a:3c:bf:a6:42:f8:ca:dc:93:67:\n                    4d:60:c3:4f:8d:c3:8a:00:1b:f1:c4:4b:41:6a:69:\n                    d2:69:e5:3f:21:8e:c5:0b:f8:22:37:ad:b6:2c:4b:\n                    55:ff:7a:03:72:bb:9a:d3:ec:96:b9:56:9f:cb:19:\n                    99:c9:32:94:6f:8f:c6:52:06:9f:45:03:df:fd:e8:\n                    97:f6:ea:d6:ba:bb:48:2b:b5:e0:34:61:4d:52:36:\n                    0f:ab:87:52:25:03:cf:87:00:87:13:f2:ca:03:29:\n                    16:9d:90:57:46:b5:f4:0e:ae:17:c8:0a:4d:92:ed:\n                    08:a6:32:23:11:71:fe:f2:2c:44:d7:6c:07:f3:0b:\n                    7b:0c:4b:dd:3b:b4:f7:37:70:9f:51:b6:88:4e:5d:\n                    6a:05:7f:8d:9b:66:7a:ab:80:20:fe:ee:6b:97:c3:\n                    49:7d:78:3b:d5:99:97:03:75:ce:8f:bc:c5:be:9c:\n                    9a:a5:12:19:70:f9:a4:bd:96:27:ed:23:02:a7:c7:\n                    57:c9:71:cf:76:94:a2:21:62:f6:b8:1d:ca:88:ee:\n                    09:ad:46:2f:b7:61:b3:2c:15:13:86:9f:a5:35:26:\n                    5a:67:f4:37:c8:e6:80:01:49:0e:c7:ed:61:d3:cd:\n                    bc:e4:f8:be:3f:c9:4e:f8:7d:97:89:ce:12:bc:ca:\n                    b5:c6:d2:e0:d9:b3:68:3c:2e:4a:9d:b4:5f:b8:53:\n                    ee:50:3d:bf:dd:d4:a2:8a:b6:a0:27:ab:98:0c:b3:\n                    b2:58:90:e2:bc:a1:ad:ff:bd:8e:55:31:0f:00:bf:\n                    68:e9:3d:a9:19:9a:f0:6d:0b:a2:14:6a:c6:4c:c6:\n                    4e:bd:63:12:a5:0b:4d:97:eb:42:09:79:53:e2:65:\n                    aa:24:34:70:b8:c1:ab:23:80:e7:9c:6c:ed:dc:82:\n                    aa:37:04:b8:43:2a:3d:2a:a8:cc:20:fc:27:5d:90:\n                    26:58:f9:b7:14:e2:9e:e2:c1:70:73:97:e9:6b:02:\n                    8e:d3:52:59:7b:00:ec:61:30:f1:56:3f:9c:c1:7c:\n                    05:c5:b1:36:c8:18:85:cf:61:40:1f:07:e8:a7:06:\n                    87:df:9a:77:0b:a9:64:72:03:f6:93:fc:e0:02:59:\n                    c1:96:ec:c0:09:42:3e:30:a2:7f:1b:48:2f:fe:e0:\n                    21:8f:53:87:25:0d:cb:ea:49:f5:4a:9b:d0:e3:5f:\n                    ee:78:18:e5:ba:71:31:a9:04:98:0f:b1:ad:67:52:\n                    a0:f2:e3:9c:ab:6a:fe:58:84:84:dd:07:3d:32:94:\n                    05:16:45:15:96:59:a0:58:6c:18:0e:e3:77:66:c7:\n                    b3:f7:99\n                Exponent: 65537 (0x10001)\n        X509v3 extensions:\n            X509v3 Basic Constraints: \n                CA:FALSE\n            Netscape Comment: \n                OpenSSL Generated Certificate\n            X509v3 Subject Key Identifier: \n                59:5F:C9:13:BA:1B:CC:B9:A8:41:4A:8A:49:79:6A:36:F6:7D:3E:D7\n            X509v3 Authority Key Identifier: \n                keyid:23:6C:2D:3D:3E:29:5D:78:B8:6C:3E:AA:E2:BB:2E:1E:6C:87:F2:53\n\n    Signature Algorithm: sha1WithRSAEncryption\n        13:e7:02:45:3e:a7:ab:bd:b8:da:e7:ef:74:88:ac:62:d5:dd:\n        10:56:d5:46:07:ec:fa:6a:80:0c:b9:62:be:aa:08:b4:be:0b:\n        eb:9a:ef:68:b7:69:6f:4d:20:92:9d:18:63:7a:23:f4:48:87:\n        6a:14:c3:91:98:1b:4e:08:59:3f:91:80:e9:f4:cf:fd:d5:bf:\n        af:4b:e4:bd:78:09:71:ac:d0:81:e5:53:9f:3e:ac:44:3e:9f:\n        f0:bf:5a:c1:70:4e:06:04:ef:dc:e8:77:05:a2:7d:c5:fa:80:\n        58:0a:c5:10:6d:90:ca:49:26:71:84:39:b7:9a:3e:e9:6f:ae:\n        c5:35:b6:5b:24:8c:c9:ef:41:c3:b1:17:b6:3b:4e:28:89:3c:\n        7e:87:a8:3a:a5:6d:dc:39:03:20:20:0b:c5:80:a3:79:13:1e:\n        f6:ec:ae:36:df:40:74:34:87:46:93:3b:a3:e0:a4:8c:2f:43:\n        4c:b2:54:80:71:76:78:d4:ea:12:28:d8:f2:e3:80:55:11:9b:\n        f4:65:dc:53:0e:b4:4c:e0:4c:09:b4:dc:a0:80:5c:e6:b5:3b:\n        95:d3:69:e4:52:3d:5b:61:86:02:e5:fd:0b:00:3a:fa:b3:45:\n        cc:c9:a3:64:f2:dc:25:59:89:58:0d:9e:6e:28:3a:55:45:50:\n        5f:88:67:2a:d2:e2:48:cc:8b:de:9a:1b:93:ae:87:e1:f2:90:\n        50:40:d9:0f:44:31:53:46:ad:62:4e:8d:48:86:19:77:fc:59:\n        75:91:79:35:59:1d:e3:4e:33:5b:e2:31:d7:ee:52:28:5f:0a:\n        70:a7:be:bb:1c:03:ca:1a:18:d0:f5:c1:5b:9c:73:04:b6:4a:\n        e8:46:52:58:76:d4:6a:e6:67:1c:0e:dc:13:d0:61:72:a0:92:\n        cb:05:97:47:1c:c1:c9:cf:41:7d:1f:b1:4d:93:6b:53:41:03:\n        21:2b:93:15:63:08:3e:2c:86:9e:7b:9f:3a:09:05:6a:7d:bb:\n        1c:a7:b7:af:96:08:cb:5b:df:07:fb:9c:f2:95:11:c0:82:81:\n        f6:1b:bf:5a:1e:58:cd:28:ca:7d:04:eb:aa:e9:29:c4:82:51:\n        2c:89:61:95:b6:ed:a5:86:7c:7c:48:1d:ec:54:96:47:79:ea:\n        fc:7f:f5:10:43:0a:9b:00:ef:8a:77:2e:f4:36:66:d2:6a:a6:\n        95:b6:9f:23:3b:12:e2:89:d5:a4:c1:2c:91:4e:cb:94:e8:3f:\n        22:0e:21:f9:b8:4a:81:5c:4c:63:ae:3d:05:b2:5c:5c:54:a7:\n        55:8f:98:25:55:c4:a6:90:bc:19:29:b1:14:d4:e2:b0:95:e4:\n        ff:89:71:61:be:8a:16:85\n-----BEGIN CERTIFICATE-----\nMIIGJzCCBA+gAwIBAgIBATANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx\nDzANBgNVBAgMBkFsc2FjZTETMBEGA1UEBwwKU3RyYXNib3VyZzEYMBYGA1UECgwP\nd3d3LmZyZWVsYW4ub3JnMRAwDgYDVQQLDAdmcmVlbGFuMS0wKwYDVQQDDCRGcmVl\nbGFuIFNhbXBsZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIjAgBgkqhkiG9w0BCQEW\nE2NvbnRhY3RAZnJlZWxhbi5vcmcwHhcNMTIwNDI3MTAzMTE4WhcNMjIwNDI1MTAz\nMTE4WjB+MQswCQYDVQQGEwJGUjEPMA0GA1UECAwGQWxzYWNlMRgwFgYDVQQKDA93\nd3cuZnJlZWxhbi5vcmcxEDAOBgNVBAsMB2ZyZWVsYW4xDjAMBgNVBAMMBWFsaWNl\nMSIwIAYJKoZIhvcNAQkBFhNjb250YWN0QGZyZWVsYW4ub3JnMIICIjANBgkqhkiG\n9w0BAQEFAAOCAg8AMIICCgKCAgEA3W29+ID6194bH6ejLrIC4hb2Ugo8v6ZC+Mrc\nk2dNYMNPjcOKABvxxEtBamnSaeU/IY7FC/giN622LEtV/3oDcrua0+yWuVafyxmZ\nyTKUb4/GUgafRQPf/eiX9urWurtIK7XgNGFNUjYPq4dSJQPPhwCHE/LKAykWnZBX\nRrX0Dq4XyApNku0IpjIjEXH+8ixE12wH8wt7DEvdO7T3N3CfUbaITl1qBX+Nm2Z6\nq4Ag/u5rl8NJfXg71ZmXA3XOj7zFvpyapRIZcPmkvZYn7SMCp8dXyXHPdpSiIWL2\nuB3KiO4JrUYvt2GzLBUThp+lNSZaZ/Q3yOaAAUkOx+1h08285Pi+P8lO+H2Xic4S\nvMq1xtLg2bNoPC5KnbRfuFPuUD2/3dSiiragJ6uYDLOyWJDivKGt/72OVTEPAL9o\n6T2pGZrwbQuiFGrGTMZOvWMSpQtNl+tCCXlT4mWqJDRwuMGrI4DnnGzt3IKqNwS4\nQyo9KqjMIPwnXZAmWPm3FOKe4sFwc5fpawKO01JZewDsYTDxVj+cwXwFxbE2yBiF\nz2FAHwfopwaH35p3C6lkcgP2k/zgAlnBluzACUI+MKJ/G0gv/uAhj1OHJQ3L6kn1\nSpvQ41/ueBjlunExqQSYD7GtZ1Kg8uOcq2r+WISE3Qc9MpQFFkUVllmgWGwYDuN3\nZsez95kCAwEAAaN7MHkwCQYDVR0TBAIwADAsBglghkgBhvhCAQ0EHxYdT3BlblNT\nTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFFlfyRO6G8y5qEFKikl5\najb2fT7XMB8GA1UdIwQYMBaAFCNsLT0+KV14uGw+quK7Lh5sh/JTMA0GCSqGSIb3\nDQEBBQUAA4ICAQAT5wJFPqervbja5+90iKxi1d0QVtVGB+z6aoAMuWK+qgi0vgvr\nmu9ot2lvTSCSnRhjeiP0SIdqFMORmBtOCFk/kYDp9M/91b+vS+S9eAlxrNCB5VOf\nPqxEPp/wv1rBcE4GBO/c6HcFon3F+oBYCsUQbZDKSSZxhDm3mj7pb67FNbZbJIzJ\n70HDsRe2O04oiTx+h6g6pW3cOQMgIAvFgKN5Ex727K4230B0NIdGkzuj4KSML0NM\nslSAcXZ41OoSKNjy44BVEZv0ZdxTDrRM4EwJtNyggFzmtTuV02nkUj1bYYYC5f0L\nADr6s0XMyaNk8twlWYlYDZ5uKDpVRVBfiGcq0uJIzIvemhuTrofh8pBQQNkPRDFT\nRq1iTo1Ihhl3/Fl1kXk1WR3jTjNb4jHX7lIoXwpwp767HAPKGhjQ9cFbnHMEtkro\nRlJYdtRq5mccDtwT0GFyoJLLBZdHHMHJz0F9H7FNk2tTQQMhK5MVYwg+LIaee586\nCQVqfbscp7evlgjLW98H+5zylRHAgoH2G79aHljNKMp9BOuq6SnEglEsiWGVtu2l\nhnx8SB3sVJZHeer8f/UQQwqbAO+Kdy70NmbSaqaVtp8jOxLiidWkwSyRTsuU6D8i\nDiH5uEqBXExjrj0FslxcVKdVj5glVcSmkLwZKbEU1OKwleT/iXFhvooWhQ==\n-----END CERTIFICATE-----\n\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data; name=\"cloud_provider\"\r\n\r\naws\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data;name=\"region\"\r\n\r\nus-east-1\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data;name=\"fqdn\"\r\n\r\ntest.com\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data; name=\"environment\"\r\n\r\ndev\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data; name=\"ticket_number\"\r\n\r\nticket-number-001\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data; name=\"tcp_upload\"\r\n\r\nno\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data; name=\"ssl_terminate_f5\"\r\n\r\nno\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data; name=\"fqdn\"\r\n\r\nfirst.app.deloitte.com\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data; name=\"load_balancing_method\"\r\n\r\nround-robin\r\n----------------------------381636933030506020173192\r\nContent-Disposition: form-data; name=\"members\"\r\n\r\n{\"members\": [{\"ip\":\"100.100.100.1\", \"port\":\"443\", \"status\":\"enabled\"},{\"ip\":\"100.100.100.2\", \"port\":\"443\", \"status\":\"disabled\"}]}\r\n----------------------------381636933030506020173192--\r\n"

    event = json.loads(event)
    event["body"] = body

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
    main()
