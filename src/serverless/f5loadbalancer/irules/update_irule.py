import re
import sys
import json
import validators
import validators
from ipaddress import ip_address

from ..common.base import BaseOperations
from ..common.connections import connection
from ..common.exceptions import CustomException
from ..common.authz import create_authz, delete_authz
from ..common.helpers import undoUpdateIRuleHelper

sys.path.append('../../')


class UpdateIRule(BaseOperations):

    def __init__(self, body, headers, queryparams, parsedParameters, *args, **kwargs):

        self.__dict__.update(kwargs)
        super().__init__(self, *args, **kwargs)
        self.body = body
        self.headers = headers
        self.queryparams = queryparams
        self.parsedParameters = parsedParameters

    def validate(self):

        # Added Validation logic here

        print("############# On validate UpdateIRule  #################")

        self.parsedParameters_dict = json.loads(self.parsedParameters)

        requiredParams = ["username", "cloud_provider", "region", "environment",
                          "tcp_upload", "fqdn"]

        optionsCloudProvider = ["aws", "azure", "gcp"]
        optionsRegion = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
        optionsEnvironment = ["dev", "stage", "prod"]
        optionsTcpUpload = ["yes", "no"]

        print("On Starting validating parameters")

        for param in requiredParams:
            if param not in self.parsedParameters_dict:
                message = "missing mandatory parameters in request body " + str(param)
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

        if (self.parsedParameters_dict["tcp_upload"] == None) or (self.parsedParameters_dict["tcp_upload"] == ""):
            self.parsedParameters_dict["tcp_upload"] = "no"
            print("Using default tcp_upload equals -no-")
        if self.parsedParameters_dict["tcp_upload"] not in optionsTcpUpload:
            msg = f"tcp_upload must be any one of {optionsTcpUpload}"
            raise CustomException(msg, code=400)

        if (self.parsedParameters_dict["fqdn"] == None) or (self.parsedParameters_dict["fqdn"] == ""):
            msg = "fqdn must be provided"
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

        if (self.parsedParameters_dict["pool_name"] == None) or (self.parsedParameters_dict["pool_name"] == ""):
            self.parsedParameters_dict["pool_name"] = self.parsedParameters_dict["fqdn"] + "_443"

        if (self.parsedParameters_dict["username"] == None) or (self.parsedParameters_dict["username"] == ""):
            msg = "username must be provided"
            raise CustomException(msg, code=400)

        self.status = "SUCCESS"


    @connection
    def operate(self):

        print("On Operate UpdateIRule")

        if self.status == 'ERROR':
            return

        try:
            self.updateIRule()

            #Authorization record creation in AuthZ was deactivate for Irules
            #create_authz(self.headers["username"], self.redirect_irule_name)

        except CustomException as error:
            if self.flagIruleUpdated:
                undoUpdateIRuleHelper(self.f5connect, self.vipName, self.parsedParameters_dict["fqdn"], self.headers["username"])
            self.status = 'ERROR'
            self.message = error.message
            self.code = error.code
            return

        except Exception as error:
            if self.flagIruleUpdated:
                undoUpdateIRuleHelper(self.f5connect, self.vipName, self.parsedParameters_dict["fqdn"], self.headers["username"])
            self.status = 'ERROR'
            self.message = "ERROR on Updating the IRULE Redirect. " + str(error)
            self.code = 500
            return

        self.status = "SUCCESS"
        self.code = 200
        self.message = "IRule was updated."


    def validateF5IPInput(self, f5_ips_list=None):
        if f5_ips_list is None:
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


    def updateIRule(self):
        try:
            self.flagIruleUpdated = False
            vip_redirect = self.f5connect.tm.ltm.virtuals.virtual.load(
                partition='Common', name=self.vipName)
            vip_irules_list = vip_redirect.rules

            redirect_irule_list = []
            for irule in vip_irules_list:
                irule_name = re.sub('/.*?/', '', irule)
                if (irule_name.startswith("rule_share")) and (irule_name.endswith("_redirect")):
                    redirect_irule_list.append(irule)

            redirect_irule = None
            redirect_irule_name = None

            if (len(redirect_irule_list)) == 1:
                irulefrag = redirect_irule_list[0].split('/')
                redirect_irule_name = name=irulefrag[2]
                self.redirect_irule_name = redirect_irule_name
                redirect_irule = self.f5connect.tm.ltm.rules.rule.load(
                    name=irulefrag[2],
                    partition=irulefrag[1]
                )
            else:
                msg = "There is more than one redirect irule on the VIP."
                raise CustomException(msg, code=409)

            irule_groups = redirect_irule.raw["apiAnonymous"].split('{')
            irule_section_1 = '{'.join(irule_groups[:2]) + "{"
            irule_section_2 = '{'.join(irule_groups[2:])

            irule_section_toadd = irule_section_toadd = """\n    "%s" {\n        pool %s\n        }""" % (
                self.parsedParameters_dict["fqdn"], self.parsedParameters_dict["pool_name"])

            updated_irule = irule_section_1 + irule_section_toadd + irule_section_2

            redirect_irule.update(apiAnonymous=updated_irule)
            self.flagIruleUpdated = True

            print("updated_irule")
            print(updated_irule)

        except CustomException as error:
            raise CustomException(error.message, code=error.code)

        except Exception as error:
            self.status = 'ERROR'
            msg = "ERROR on Updating the IRULE Redirect. " + str(error)
            raise CustomException(msg, code=500)



if __name__ == "__main__":
    pass
