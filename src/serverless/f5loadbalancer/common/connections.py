import os
import yaml
import json
import boto3
import netaddr
from io import BytesIO
from functools import wraps
from f5.bigip import ManagementRoot
from .exceptions import CustomException
from icontrol.exceptions import iControlUnexpectedHTTPError


class ParseYaml():
    def __init__(self, region_name, tcp_upload, deploy_environment = 'dev',  provider = 'aws' ):
        self.region_name = region_name
        self.provider = provider
        self.deploy_environment = deploy_environment
        self.tcp_upload = tcp_upload

    def read_input_file(self, filecontent=None):
        try:
            mapping_data = yaml.load(filecontent, Loader=yaml.FullLoader)
            return self.apply_input_conditions(mapping_data[self.provider][self.region_name][self.deploy_environment])
        except Exception as e:
            print("Exception raised while reading file content. Error: " + str(e))
            msg = "Could not get IP for F5 Server. Error: " + str(e)
            raise CustomException(msg, code=500)

    def apply_input_conditions( self, data ):
        f5_parameters, tcp_upload_parameters, redirect_parameters = data.values()
        f5_ip1, f5_port1, f5_ip2, f5_port2 = f5_parameters.values()
        if self.tcp_upload == 'yes':
            vip_name = tcp_upload_parameters['vip']
        if self.tcp_upload == 'no':
            vip_name = redirect_parameters['vip']
        print( f5_ip1, f5_port1, f5_ip2, f5_port2, vip_name )
        return f5_ip1, f5_port1, f5_ip2, f5_port2, vip_name


def get_secret(f5ip):

    try:
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager',
                                region_name='us-east-1')

        SECRET_MANAGER_ID = os.environ['SECRET_MANAGER_ID']

        get_secret_value_response = client.get_secret_value(
                                     SecretId=SECRET_MANAGER_ID)

        SecretString = get_secret_value_response['SecretString']
        SecretString_dict = json.loads(SecretString)
        f5ip_credentials = SecretString_dict[f5ip]
        f5username = f5ip_credentials['f5username']
        f5secret = f5ip_credentials['f5secret']

        return(f5username, f5secret)

    except Exception as error:
        msg = "Could not get Secrets for F5 IP. Error: " + str(error)
        raise CustomException(msg, code=500)


def getF5IPs(region_name, tcp_upload, provider, environment):
    try:
        print("--------------In get F5 API function----------------")
        s3_session = boto3.session.Session()
        client = s3_session.client(
            service_name= 's3',
            region_name= 'us-east-1'
        )
        bucket_name = os.environ['S3_BUCKET_NAME']
        bucket_filename = os.environ['S3_BUCKET_FILENAME']
        result = client.get_object(Bucket=bucket_name, Key=bucket_filename)
        file_content_string = result['Body'].read().decode('utf-8')
        parse_obj = ParseYaml(region_name, tcp_upload, provider=provider, deploy_environment=environment)
        f5_parameters = parse_obj.read_input_file( file_content_string )
        return f5_parameters

    except Exception as e:
        print( "Exception raised in getF5IPs function. " + str(e))
        message = "Could not get the F5 IPs, ports and Vip"
        raise CustomException(message, code = 500)


def connection(func):
    @wraps(func)
    def update_status(self, *args, **kwargs):
        self.message = 'Error calling connection function'
        self.status = 'ERROR'
        self.code = 500
        try:

            if (self.parsedParameters_dict["f5_ips"] == None) or (self.parsedParameters_dict["f5_ips"] == ""):

                self.f5ip, self.f5port, self.f5ip2, self.f5port2, self.vipName = getF5IPs(self.parsedParameters_dict['region'], self.parsedParameters_dict['tcp_upload'], self.parsedParameters_dict['cloud_provider'], self.parsedParameters_dict['environment'])

            elif len(self.parsedParameters_dict["f5_ips"]["f5_ips"])==1:
                self.f5ip = self.parsedParameters_dict["f5_ips"]["f5_ips"][0]["ip"]
                self.f5port = int(self.parsedParameters_dict["f5_ips"]["f5_ips"][0]["port"])
                self.vipName = self.parsedParameters_dict["vip_name"]
                self.f5ip2 = None
                self.f5port2 = None
            elif len(self.parsedParameters_dict["f5_ips"]["f5_ips"])==2:
                self.f5ip = self.parsedParameters_dict["f5_ips"]["f5_ips"][0]["ip"]
                self.f5port = int(self.parsedParameters_dict["f5_ips"]["f5_ips"][0]["port"])
                self.f5ip2 = self.parsedParameters_dict["f5_ips"]["f5_ips"][1]["ip"]
                self.f5port2 = int(self.parsedParameters_dict["f5_ips"]["f5_ips"][1]["port"])
                self.vipName = self.parsedParameters_dict["vip_name"]
            else:
                msg = "Error connecting to F5 Servers. Error on processing f5_ips."
                raise CustomException(msg, code=500)


            username1, secret1 = get_secret(self.f5ip)

            try:
                print("Starting connection to F5 Server 1")
                self.f5connect = ManagementRoot(
                    self.f5ip, username1, secret1, port=self.f5port)
                self.f5connect2 = ""
                print("Connection to F5 Server 1 Sucessfull")

            except Exception as error:
                msg = "Error connectiong to F5 Server 1."
                raise CustomException(msg, code=500)

            if self.f5ip2 is not None:
                username2, secret2 = get_secret(self.f5ip2)
                try:
                    print("Starting connection to F5 Server 2")
                    self.f5connect2 = ManagementRoot(
                        self.f5ip2, username2, secret2, port=self.f5port2)
                    print("Connection to F5 Server 2 Sucessfull")
                except Exception as error:
                    msg = "Error connectiong to F5 Server 2."
                    raise CustomException(msg, code=500)


            self.message = 'Connection Successful but no\
                             message returned from operate() function'
            self.status = 'SUCCESS'
            self.code = 200

            func(self)

        except iControlUnexpectedHTTPError as err:
            try:
                print(err)
                self.message = str(err.response.json()['message'])
            except Exception:
                self.message = str(err.response.reason)
            self.code = 500
            self.err = err
        except CustomException as error:
            print(error)
            self.message = str(error.message)
            self.code = error.code
        except Exception as e:
            print(e)
            self.message = str(e)
            self.err = e
            self.code = 500
    return update_status


if __name__ == '__main__':
    pass
