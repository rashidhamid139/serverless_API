import sys
import json
import os
from os import path
import validators
from ipaddress import ip_address

from pool_handler import mainPool
from irule_handler import mainIRule
from certificate_handler import mainCertificate

from ..common.exceptions import CustomException
from ..common.connections import connection
from ..common.base import BaseOperations
from ..common.helpers import deleteCertificateALLHelper, deletePollAndMembersHelper, undoUpdateIRuleHelper


sys.path.append('../../')


class CreateIngress(BaseOperations):
    def __init__(self, body, headers, queryparams, parsedParameters, *args, **kwargs):

        self.__dict__.update(kwargs)
        super().__init__(self, *args, **kwargs)
        self.body = body
        self.headers = headers
        self.queryparams = queryparams
        self.parsedParameters = parsedParameters
        print("-----")
        print(self.parsedParameters)

    def validate(self):
        # Added Validation logic here

        print("On validate CreateIngress")

        self.parsedParameters_dict = json.loads(self.parsedParameters)

        requiredParams = ["username", "cloud_provider", "region", "environment", "ticket_number",
                          "tcp_upload", "ssl_terminate_f5", "fqdn", "health_monitor", "load_balancing_method",
                          "members", "key_file", "cert_file", "file_path_key", "file_path_cert"]

        optionsCloudProvider = ["aws", "azure", "gcp"]
        optionsRegion = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
        optionsEnvironment = ["dev", "stage", "prod"]
        optionsTcpUpload = ["yes", "no"]
        optionsSslTerminateF5 = ["yes", "no"]
        optionsHealthMonitor = ["tcp", "http", "https"]
        optionsLoadBalancingMethod = ["predictive-member", "round-robin", "ratio-member", "observed-member",
                                      "ratio-node", "fastest-node", "obsereved-node", "predictive-node", "ratio-session"]

        print("On Starting validating parameters")

        for param in requiredParams:
            if param not in self.parsedParameters_dict:
                message = "Missing mandatory parameters in request body " + str(param)
                raise CustomException(message, code=400)

        if self.parsedParameters_dict["cloud_provider"] not in optionsCloudProvider:
            msg = f"optionsCloudProvider must be any one of {optionsCloudProvider}"
            raise CustomException(msg, code=400)

        if self.parsedParameters_dict["region"] not in optionsRegion:
            msg = f"region must be any one of {optionsRegion}"
            raise CustomException(msg, code=400)

        if self.parsedParameters_dict["environment"] not in optionsEnvironment:
            msg = f"environment must be any one of {optionsEnvironment}"
            raise CustomException(msg, code=400)

        if (self.parsedParameters_dict["ticket_number"] == None) or (self.parsedParameters_dict["ticket_number"] == ""):
            msg = "ticket_number must be provided"
            raise CustomException(msg, code=400)

        if (self.parsedParameters_dict["tcp_upload"] == None) or (self.parsedParameters_dict["tcp_upload"] == ""):
            self.parsedParameters_dict["tcp_upload"] = "no"
            print("Using default tcp_upload equals -no-")
        if self.parsedParameters_dict["tcp_upload"] not in optionsTcpUpload:
            msg = f"tcp_upload must be any one of {optionsTcpUpload}"
            raise CustomException(msg, code=400)

        if self.parsedParameters_dict["ssl_terminate_f5"] not in optionsSslTerminateF5:
            msg = f"ssl_terminate_f5 must be any one of {optionsSslTerminateF5}"
            raise CustomException(msg, code=400)

        if (self.parsedParameters_dict["health_monitor"] == None) or (self.parsedParameters_dict["health_monitor"] == ""):
            self.parsedParameters_dict["health_monitor"] = "tcp"
            print("Using default health_monitor equals -tcp-")
        if self.parsedParameters_dict["health_monitor"] not in optionsHealthMonitor:
            msg = f"health_monitor must be any one of {optionsHealthMonitor}"
            raise CustomException(msg, code=400)

        if self.parsedParameters_dict["load_balancing_method"] not in optionsLoadBalancingMethod:
            msg = f"load_balancing_method must be any one of {optionsLoadBalancingMethod}"
            raise CustomException(msg, code=400)

        if (self.parsedParameters_dict["members"] == None) or (self.parsedParameters_dict["members"] == ""):
            raise CustomException("members parameter is missing", code=400)
        try:
            flag_string = isinstance(
                self.parsedParameters_dict["members"], str)
            if (flag_string):
                self.parsedParameters_dict["members"] = self.parsedParameters_dict["members"].replace(
                    "'", "\"")
                self.parsedParameters_dict["members"] = json.loads(
                    self.parsedParameters_dict["members"])
            if type(self.parsedParameters_dict["members"]["members"]) is not list:
                raise CustomException(
                    "members parameter must be a list", code=400)
        except CustomException as error:
            raise CustomException(error.message, code=error.code)
        except Exception as error:
            msg = "members parameter is not formated properly"
            raise CustomException(msg, code=400)
        try:
            msg, valid = self.validateMemberInput(
                self.parsedParameters_dict["members"]["members"])
            if valid:
                pass
            else:
                raise CustomException(msg, code=400)
        except CustomException as error:
            raise CustomException(error.message, code=error.code)
        except Exception as error:
            msg = "Error validating members parameters"
            raise CustomException(msg, code=400)


        if (self.parsedParameters_dict["f5_ips"] == None) or (self.parsedParameters_dict["f5_ips"] == ""):
            self.parsedParameters_dict["f5_ips"] = ""

        else:
            try:
                flag_string = isinstance(
                    self.parsedParameters_dict["f5_ips"], str)
                if (flag_string):
                    self.parsedParameters_dict["f5_ips"] = self.parsedParameters_dict["f5_ips"].replace(
                        "'", "\"")
                    self.parsedParameters_dict["f5_ips"] = json.loads(
                        self.parsedParameters_dict["f5_ips"])
                if type(self.parsedParameters_dict["f5_ips"]["f5_ips"]) is not list:
                    raise CustomException(
                        "f5_ips parameter must be a list", code=400)
                elif len(self.parsedParameters_dict["f5_ips"]["f5_ips"])==0 or len(self.parsedParameters_dict["f5_ips"]["f5_ips"])>2:
                    raise CustomException(
                        "f5_ips parameter must be a list of 1 or 2 F5 IP:port", code=400)
                elif len(self.parsedParameters_dict["f5_ips"]["f5_ips"])==1 and self.parsedParameters_dict["cloud_provider"]=="azure":
                    raise CustomException(
                        "f5_ips parameter are invalid. Cloud provider Azure requires to configure two F5 IP:port - HA configuration active-active", code=400)
                else:
                    pass
            except CustomException as error:
                raise CustomException(error.message, code=error.code)
            except Exception as error:
                msg = "f5_ips parameter is not formated properly"
                raise CustomException(msg, code=400)
            try:
                msg, valid = self.validateF5IPInput(
                    self.parsedParameters_dict["f5_ips"]["f5_ips"])
                if valid:
                    pass
                else:
                    raise CustomException(msg, code=400)
            except CustomException as error:
                raise CustomException(error.message, code=error.code)
            except Exception as error:
                msg = "Error validating f5_ips parameters"
                raise CustomException(msg, code=400)
            try:
                if (self.parsedParameters_dict["vip_name"] == None) or (self.parsedParameters_dict["vip_name"] == ""):
                    raise CustomException("vip_name parameter is missing as given f5_ips", code=400)
            except CustomException as error:
                raise CustomException(error.message, code=error.code)
            except Exception as error:
                msg = "Error validating vip_name parameter"
                raise CustomException(msg, code=400)

        if not ((self.parsedParameters_dict["vip_name"] == None) or (self.parsedParameters_dict["vip_name"] == "")):
            if (self.parsedParameters_dict["f5_ips"] == None) or (self.parsedParameters_dict["f5_ips"] == ""):
                msg = "If vip_name is provided, f5_ips list must be provided"
                raise CustomException(msg, code=400)

        if (self.parsedParameters_dict["fqdn"] == None) or (self.parsedParameters_dict["fqdn"] == ""):
            msg = "fqdn must be provided"
            raise CustomException(msg, code=400)

        if (self.parsedParameters_dict["username"] == None) or (self.parsedParameters_dict["username"] == ""):
            msg = "username must be provided"
            raise CustomException(msg, code=400)


        if (self.parsedParameters_dict["key_file"] == None) or (self.parsedParameters_dict["key_file"] == ""):
            msg = "key_file must be provided"
            raise CustomException(msg, code=400)

        if ((path.exists(str(self.parsedParameters_dict["file_path_key"]))) and (path.isfile(str(self.parsedParameters_dict["file_path_key"])))):
            print("File Key does exist")
            if os.stat(str(self.parsedParameters_dict["file_path_key"])).st_size == 0:
                print("File Key is empty")
                msg = "key_file must not be empty"
                raise CustomException(msg, code=400)
        else:
            print("File Key does not exist")
            msg = "key_file must be provided"
            raise CustomException(msg, code=400)


        if (self.parsedParameters_dict["cert_file"] == None) or (self.parsedParameters_dict["cert_file"] == ""):
            msg = "cert_file must be provided"
            raise CustomException(msg, code=400)

        if ((path.exists(str(self.parsedParameters_dict["file_path_cert"]))) and (path.isfile(str(self.parsedParameters_dict["file_path_cert"])))):
            print("File Cert does exist")
            if os.stat(str(self.parsedParameters_dict["file_path_cert"])).st_size == 0:
                print("File Cert is empty")
                msg = "cert_file must not be empty"
                raise CustomException(msg, code=400)
        else:
            print("File Cert does not exist")
            msg = "cert_file must be provided"
            raise CustomException(msg, code=400)


        self.status = "SUCCESS"

    @connection
    def operate(self):

        print("On OPERATE Create Ingress")

        if self.status == 'ERROR':
            return

        try:
            # -- Operations here

            # --- Certificate Creation
            self.createCert()
            if self.status == "ERROR":
                self.message = "ERROR creating Certificate. " + self.message
                return

            # --- Pool and Members Creation
            self.createPool()
            if self.status == "ERROR":
                self.deleteCertificateAll()
                self.message = "ERROR creating the Pool and Members. " + self.message
                return

            # --- Updating IRULE
            self.updateIRule()
            if self.status == "ERROR":
                self.deletePollAndMembers()
                self.deleteCertificateAll()
                self.undoUpdateIRule()
                self.message = "ERROR updating the Irule. " + self.message
                return

            self.status = "SUCCESS"
            self.code = 200
            self.message = "INGRESS WAS CREATED SUCCESSFULLY."

        except CustomException as error:
            self.status = 'ERROR'
            self.message = error.message
            self.code = error.code
            return

        except Exception as error:
            self.status = 'ERROR'
            self.message = "ERROR on Creating Ingress." + str(error)
            self.code = 500
            return


    def validateMemberInput(self, member_list=None):
        if member_list is None or not isinstance(member_list, list) or len(member_list) == 0:
            return "Empty Member List", False
        member_status = ['enabled', 'disabled']
        for mem in member_list:
            status = mem['status']
            if status not in member_status:
                return "Invalid member status, Status can be either enabled or disabled", False

            port = mem['port']
            try:
                port = int(port)
                if isinstance(port, int) and int(port) > 1 and int(port) < 65535:
                    pass
                else:
                    return f"Invalid member Port, port value must be a valid port for member {mem}", False
            except:
                return f"Invalid member Port, port value must be an numeric type for member {mem}", False

            ip = mem['ip']
            try:
                if ip_address(ip):
                    pass
                else:
                    return f"Invalid IP for member {mem}", False
            except:
                return f"Invalid IP for member {mem}", False
        return "All Valid Members", True


    def validateF5IPInput(self, f5_ips_list=None):
        if f5_ips_list is None or not isinstance(f5_ips_list, list) or len(f5_ips_list) == 0:
            return "Empty f5_ips List", False

        for f5ip in f5_ips_list:

            port = f5ip['port']
            try:
                port = int(port)
                if isinstance(port, int) and int(port) > 1 and int(port) < 65535:
                    pass
                else:
                    return f"Invalid f5_ips Parameter, port value must be a valid port for f5_ip {f5ip}", False
            except:
                return f"Invalid f5_ips Parameter, port value must be an numeric type for f5_ip {f5ip}", False

            ip = f5ip['ip']
            try:
                if ip_address(ip):
                    pass
                else:
                    return f"Invalid IP for f5_ip {f5ip}", False
            except:
                return f"Invalid IP for f5_ip {f5ip}", False
        return "All Valid f5_ips", True


    def createCert(self):

        # --- Certificate Creation - TO BE REPLACED FOR NEW API CREATE CERT
        try:
            event = {}
            event["body"] = self.body
            event["headers"] = self.headers
            event["queryStringParameters"] = self.queryparams
            event["httpMethod"] = "POST"

            print("############# Before mainCertificate  #################")

            response = mainCertificate(event)

            self.status = json.loads(response["body"])["status"]
            self.message = json.loads(response["body"])["message"]
            self.code = response["statusCode"]

            print("############# After mainCertificate  #################")

        except Exception as error:
            self.status = 'ERROR'
            self.message = "ERROR on Create Certificate. " + str(error)
            self.code = 500
            return
        # --- Certificate Creation - END

    def updateIRule(self):

        # --- Update IRULE - TO BE REPLACED FOR NEW API UPDATE IRULE

        try:
            print("On updateIRule")

            template_api = """{
                "resource": "/irules",
                "path": "/irules",
                "httpMethod": "POST",
                "queryStringParameters": null,
                "multiValueQueryStringParameters": null,
                "pathParameters": null,
                "stageVariables": null,
                "body": {
                    "cloud_provider": "%s",
                    "region": "%s",
                    "environment": "%s",
                    "tcp_upload": "%s",
                    "fqdn": "%s",
                    "pool_name": "%s",
                    "f5_ips": "%s",
                    "vip_name": "%s"
                },
                "isBase64Encoded": false
            }""" % (self.parsedParameters_dict["cloud_provider"], self.parsedParameters_dict["region"], self.parsedParameters_dict["environment"], self.parsedParameters_dict["tcp_upload"], self.parsedParameters_dict["fqdn"], self.parsedParameters_dict["fqdn"]+"_443", self.parsedParameters_dict["f5_ips"], self.parsedParameters_dict["vip_name"])

            template_api = json.loads(template_api)

            event = {}
            event["body"] = template_api["body"]
            event["headers"] = self.headers
            event["queryStringParameters"] = template_api["queryStringParameters"]
            event["httpMethod"] = template_api["httpMethod"]

            response = mainIRule(event)

            self.status = json.loads(response["body"])["status"]
            self.message = json.loads(response["body"])["message"]
            self.code = response["statusCode"]

            print("############# After updateIRule  #################")

        except Exception as error:
            self.status = 'ERROR'
            self.message = "ERROR. " + str(error)
            self.code = 500
            return
        # --- Update IRULE - END

    def createPool(self):

        # --- Create Pool - TO BE REPLACED FOR NEW API CREATE POOL

        try:
            print("On createPool")

            template_api = """{
                "resource": "/pools",
                "path": "/pools",
                "httpMethod": "POST",
                "queryStringParameters": null,
                "multiValueQueryStringParameters": null,
                "pathParameters": null,
                "stageVariables": null,
                "body": {
                    "cloud_provider": "%s",
                    "region": "%s",
                    "environment": "%s",
                    "tcp_upload": "%s",
                    "fqdn": "%s",
                    "health_monitor": "%s",
                    "load_balancing_method": "%s",
                    "members": "%s",
                    "ticket_number": "%s",
                    "f5_ips": "%s",
                    "vip_name": "%s"
                },
                "isBase64Encoded": false
            }""" % (self.parsedParameters_dict["cloud_provider"], self.parsedParameters_dict["region"], self.parsedParameters_dict["environment"], self.parsedParameters_dict["tcp_upload"], self.parsedParameters_dict["fqdn"], self.parsedParameters_dict["health_monitor"], self.parsedParameters_dict["load_balancing_method"], self.parsedParameters_dict["members"], self.parsedParameters_dict["ticket_number"], self.parsedParameters_dict["f5_ips"], self.parsedParameters_dict["vip_name"])

            template_api = json.loads(template_api)

            event = {}
            event["body"] = template_api["body"]
            event["headers"] = self.headers
            event["queryStringParameters"] = template_api["queryStringParameters"]
            event["httpMethod"] = template_api["httpMethod"]

            response = mainPool(event)

            self.status = json.loads(response["body"])["status"]
            self.message = json.loads(response["body"])["message"]
            self.code = response["statusCode"]

            print("############# After createPool  #################")

        except Exception as error:
            self.status = 'ERROR'
            self.message = "ERROR. " + str(error)
            self.code = 500
            return
        # --- Create Pool - END

    ################### --- DELETE / UNDO Functions below --- ###################

    def deleteCertificateAll(self):
        # --- Deletion of resources created by createCert
        try:

            print("############# Before deleteCertificateALL  #################")

            deleteCertificateALLHelper(self.f5connect, self.f5connect2, self.vipName, self.parsedParameters_dict[
                                       "cloud_provider"], self.parsedParameters_dict["ssl_terminate_f5"], self.parsedParameters_dict["fqdn"], self.headers["username"])


            print("############# After deleteCertificateALL  #################")

        except Exception as error:
            self.status = 'ERROR'
            self.message = "ERROR on deleteCertificateALL. " + str(error)
            self.code = 500
            return
        # --- Deletion of resources created by Create Certificate - END


    def deletePollAndMembers(self):
        # --- Undo the Create Pool and members by createPool
        try:

            print("############# Before deletePollAndMembers  #################")

            pool_name = self.parsedParameters_dict["fqdn"] + "_443"

            deletePollAndMembersHelper(self.f5connect, pool_name, self.headers["username"])


            print("############# After deletePollAndMembers  #################")

        except Exception as error:
            self.status = 'ERROR'
            self.message = "ERROR on deletePollAndMembers. " + str(error)
            self.code = 500
            return
        # --- Undo the Update of the IRULE by updateIRule - END


    def undoUpdateIRule(self):
        # --- Undo the Update of the IRULE by updateIRule
        try:

            print("############# Before undoUpdateIRule  #################")

            undoUpdateIRuleHelper(
                self.f5connect, self.vipName, self.parsedParameters_dict["fqdn"], self.headers["username"])


            print("############# After undoUpdateIRule  #################")

        except Exception as error:
            self.status = 'ERROR'
            self.message = "ERROR on undoUpdateIRule. " + str(error)
            self.code = 500
            return
        # --- Undo the Update of the IRULE by updateIRule - END


if __name__ == '__main__':
    pass
