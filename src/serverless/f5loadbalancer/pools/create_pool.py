import re
import sys
import json
import validators
from ipaddress import ip_address

from ..common.base import BaseOperations
from ..common.connections import connection
from ..common.exceptions import CustomException
from ..common.authz import create_authz, delete_authz
from ..common.helpers import deletePollAndMembersHelper



sys.path.append('../../')


class CreatePool(BaseOperations):

    def __init__(self, body, headers, queryparams, parsedParameters, *args, **kwargs):

        self.__dict__.update(kwargs)
        super().__init__(self, *args, **kwargs)
        self.body = body
        self.headers = headers
        self.queryparams = queryparams
        self.parsedParameters = parsedParameters

    def validate(self):

        # Added Validation logic here

        print("############# On validate CreatePool  #################")

        self.parsedParameters_dict = json.loads(self.parsedParameters)

        requiredParams = ["username", "cloud_provider", "region", "environment",
                          "tcp_upload", "fqdn", "health_monitor", "load_balancing_method", "members"]

        optionsCloudProvider = ["aws", "azure", "gcp"]
        optionsRegion = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
        optionsEnvironment = ["dev", "stage", "prod"]
        optionsTcpUpload = ["yes", "no"]
        optionsLoadBalancingMethod = ["predictive-member", "round-robin", "ratio-member", "observed-member",
                                      "ratio-node", "fastest-node", "obsereved-node", "predictive-node", "ratio-session"]
        optionsHealthMonitor = ["tcp", "http", "https"]
        optionsMemberStatus = ["enabled", "disabled"]

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

        if self.parsedParameters_dict["load_balancing_method"] not in optionsLoadBalancingMethod:
            msg = f"load_balancing_method must be any one of {optionsLoadBalancingMethod}"
            raise CustomException(msg, code=400)

        if (self.parsedParameters_dict["health_monitor"] == None) or (self.parsedParameters_dict["health_monitor"] == ""):
            self.parsedParameters_dict["health_monitor"] = "tcp"
            print("Using default health_monitor equals -tcp-")
        if self.parsedParameters_dict["health_monitor"] not in optionsHealthMonitor:
            msg = f"health_monitor must be any one of {optionsHealthMonitor}"
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

        if (self.parsedParameters_dict["pool_name"] == None) or (self.parsedParameters_dict["pool_name"] == ""):
            self.parsedParameters_dict["pool_name"] = self.parsedParameters_dict["fqdn"] + "_443"

        if (self.parsedParameters_dict["ticket_number"] == None) or (self.parsedParameters_dict["ticket_number"] == ""):
            msg = "ticket_number must be provided"
            raise CustomException(msg, code=400)

        if (self.parsedParameters_dict["username"] == None) or (self.parsedParameters_dict["username"] == ""):
            msg = "username must be provided"
            raise CustomException(msg, code=400)

        self.status = "SUCCESS"


    @connection
    def operate(self):

        print("On Operate CreatePool")

        if self.status == 'ERROR':
            return

        try:

            self.createPool()

            create_authz(self.headers["username"], self.parsedParameters_dict["pool_name"])

        except CustomException as error:
            if self.flagPoolCreated:
                deletePollAndMembersHelper(self.f5connect, self.parsedParameters_dict["pool_name"], self.headers["username"])
            self.status = 'ERROR'
            self.message = error.message
            self.code = error.code
            return

        except Exception as error:
            if self.flagPoolCreated:
                deletePollAndMembersHelper(self.f5connect, self.parsedParameters_dict["pool_name"], self.headers["username"])
            self.status = 'ERROR'
            self.message = "ERROR on Creating Pool. " + str(error)
            self.code = 500
            return

        self.status = "SUCCESS"
        self.code = 200
        self.message = "Pool was created."

    def validateMemberInput(self, member_list=None):
        if member_list is None or not isinstance(member_list, list) or len(member_list) == 0:
            return "Empty Member List", False
        member_status = ['enabled', 'disabled']
        for mem in member_list:
            status = mem['status']
            if status not in member_status:
                return "Invalid member parameters, Status can be either enabled or disabled", False

            port = mem['port']
            try:
                port = int(port)
                if isinstance(port, int) and int(port) > 1 and int(port) < 65535:
                    pass
                else:
                    return f"Invalid member Parameter, port value must be a valid port for member {mem}", False
            except:
                return f"Invalid member Parameter, port value must be an numeric type for member {mem}", False

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


    def createPool(self):

        try:
            self.flagPoolCreated = False
            pool_name = self.parsedParameters_dict["pool_name"]

            all_pools = [
                pool.name for pool in self.f5connect.tm.ltm.pools.get_collection()]

            if pool_name in all_pools:
                print("In Pool already exist")
                msg = f"{pool_name} already exist"
                raise CustomException(msg, code=409)
            else:
                try:
                    new_pool_obj = self.f5connect.tm.ltm.pools.pool.create(name=pool_name, partition='Common', loadBalancingMode=self.parsedParameters_dict[
                                                                           "load_balancing_method"], monitor=self.parsedParameters_dict["health_monitor"], description=self.parsedParameters_dict["ticket_number"])

                    if self.f5connect.tm.ltm.pools.pool.exists(name=pool_name, partition='Common'):
                        try:
                            self.addMembers(
                                pool_name, self.parsedParameters_dict["members"])
                            self.flagPoolCreated = True
                            print("Pool was created")
                        except CustomException as error:
                            deletePollAndMembersHelper(self.f5connect, pool_name, self.headers["username"])
                            raise CustomException(error.message, code=error.code)
                        except Exception as error:
                            deletePollAndMembersHelper(self.f5connect, pool_name, self.headers["username"])
                            msg = "Pool was not properly created. Error adding members"
                            raise CustomException(msg, code=500)
                    else:
                        msg = "Pool was not properly created."
                        raise CustomException(msg, code=500)
                except CustomException as error:
                    if self.f5connect.tm.ltm.pools.pool.exists(name=pool_name, partition='Common'):
                        deletePollAndMembersHelper(self.f5connect, pool_name, self.headers["username"])
                    raise CustomException(error.message, code=error.code)
                except Exception as error:
                    if self.f5connect.tm.ltm.pools.pool.exists(name=pool_name, partition='Common'):
                        deletePollAndMembersHelper(self.f5connect, pool_name, self.headers["username"])
                    msg = "Pool was not properly created."
                    raise CustomException(msg, code=500)

        except CustomException as error:
            raise CustomException(error.message, code=error.code)

        except Exception as error:
            msg = "ERROR on Creating the Pool. " + str(error)
            raise CustomException(msg, code=500)

    def addMembers(self, pool_name, members_list=None):

        if members_list is  None or len(members_list.get("members", [] ) ) == 0:
            raise CustomException('Empty members passed in request', code=400)

        all_pools = [
            pool.name for pool in self.f5connect.tm.ltm.pools.get_collection()]

        if pool_name in all_pools:
            pool_obj = self.f5connect.tm.ltm.pools.pool.load(
                partition='Common', name=pool_name)
            for member in members_list['members']:
                member_name = "Node_" + member['ip'] + ":" + member['port']
                member_session = "user-" + member['status']
                print(member_name)
                if not pool_obj.members_s.members.exists(partition='Common', name=member_name):
                    print("Adding a new member")
                    try:
                        pool_obj.members_s.members.create(partition='Common', name=member_name, address=str(
                            member['ip']), session=member_session)
                    except Exception as e:
                        msg = "Error creating member. " + str(e)
                        raise CustomException(msg, code=500)
        else:
            msg = "Pool doesn't exist"
            raise CustomException(msg, code=400)


if __name__ == "__main__":
    pass
