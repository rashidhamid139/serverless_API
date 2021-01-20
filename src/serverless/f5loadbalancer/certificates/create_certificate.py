import sys
import json
import os
from os import path
import validators
from ipaddress import ip_address

from ..common.base import BaseOperations
from ..common.connections import connection
from ..common.exceptions import CustomException
from ..common.authz import create_authz, delete_authz
from ..common.helpers import deleteSystemSsl, deleteLocalClientSslProfile, deleteLocalServerSslProfile, deleteClientSslProfileVip, deleteServerSslProfileVip

sys.path.append('../../')


class CreateCert(BaseOperations):
    def __init__(self, body, headers, queryparams, parsedParameters, *args, **kwargs):

        self.__dict__.update(kwargs)
        super().__init__(self, *args, **kwargs)
        self.body = body
        self.headers = headers
        self.queryparams = queryparams
        self.parsedParameters = parsedParameters

    def validate(self):
        # Added Validation logic here

        print("############# On validate CreateCert  #################")

        self.parsedParameters_dict = json.loads(self.parsedParameters)

        requiredParams = ["username", "cloud_provider", "region", "environment",
                          "tcp_upload", "ssl_terminate_f5", "fqdn",
                          "key_file", "cert_file", "file_path_key", "file_path_cert"]

        optionsCloudProvider = ["aws", "azure", "gcp"]
        optionsRegion = ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
        optionsEnvironment = ["dev", "stage", "prod"]
        optionsTcpUpload = ["yes", "no"]
        optionsSslTerminateF5 = ["yes", "no"]

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

        if self.parsedParameters_dict["ssl_terminate_f5"] not in optionsSslTerminateF5:
            msg = f"ssl_terminate_f5 must be any one of {optionsSslTerminateF5}"
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

        # -- Operations here
        print("OPERATE CERT")

        if self.status == 'ERROR':
            return

        ###########################################
        try:    # Uploading Files into F5 Server
            print("Uploading Files into F5 Server")
            file_up = self.f5connect.shared.file_transfer.uploads.upload_file(
                self.parsedParameters_dict["file_path_key"])
            file_up = self.f5connect.shared.file_transfer.uploads.upload_file(
                self.parsedParameters_dict["file_path_cert"])
        except Exception as error:
            print(error)
            self.status = 'ERROR'
            self.message = "ERROR on Create Certificate - Uploading Files. " + \
                str(error)
            self.code = 500
            return

        ###########################################
        try:    # Creating System SSL Certs (Key and Cert)
            print("Creating System SSL Certs")

            self.flagSystemSslCreated = False

            sourcePathKey = 'file:/var/config/rest/downloads/' + \
                self.parsedParameters_dict["key_file"]
            sourcePathCert = 'file:/var/config/rest/downloads/' + \
                self.parsedParameters_dict["cert_file"]
            systemSslName = 'ssl_' + self.parsedParameters_dict["fqdn"]

            all_system_ssl_certs = self.f5connect.tm.sys.file.ssl_certs.get_collection()
            existing_system_ssl_certs = [
                cert.name for cert in all_system_ssl_certs]

            if systemSslName not in existing_system_ssl_certs:
                cert = self.f5connect.tm.sys.file.ssl_certs.ssl_cert.create(
                    name=systemSslName, partition='Common', sourcePath=sourcePathCert)
            else:
                msg = f"System SSL Certificate with name {systemSslName} already exist"
                raise CustomException(msg, code=409)

            all_system_ssl_keys = self.f5connect.tm.sys.file.ssl_keys.get_collection()
            existing_system_ssl_keys = [
                key.name for key in all_system_ssl_keys]

            if systemSslName not in existing_system_ssl_keys:
                key = self.f5connect.tm.sys.file.ssl_keys.ssl_key.create(
                    name=systemSslName, partition='Common', sourcePath=sourcePathKey)
            else:
                system_cert_todelete = self.f5connect.tm.sys.file.ssl_certs.ssl_cert.load(
                    name=systemSslName)
                system_cert_todelete.delete()
                msg = f"System SSL Key with name {systemSslName} already exist"
                raise CustomException(msg, code=409)

            self.flagSystemSslCreated = True

            create_authz(self.headers["username"], systemSslName)

        except CustomException as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagSystemSslCreated:
                deleteSystemSsl(self.f5connect, systemSslName)
                delete_authz(self.headers["username"], systemSslName)
            self.status = 'ERROR'
            self.message = error.message
            self.code = error.code
            return

        except Exception as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagSystemSslCreated:
                deleteSystemSsl(self.f5connect, systemSslName)
                delete_authz(self.headers["username"], systemSslName)
            self.status = 'ERROR'
            self.message = "ERROR on Create Certificate - Creating System SSL Certs. " + \
                str(error)
            self.code = 500
            return

        ###########################################
        try:    # Creating Local Client SSL Profile
            print("Creating Local Client SSL Profile")
            self.flagClientSslProfileCreated = False

            systemSSLPath = "/Common/" + systemSslName

            clientSslProfileName = 'clientssl_' + \
                self.parsedParameters_dict["fqdn"]

            all_local_client_ssl = self.f5connect.tm.ltm.profile.client_ssls.get_collection()
            existing_local_client_ssl = [
                client.name for client in all_local_client_ssl]

            if clientSslProfileName not in existing_local_client_ssl:
                ssl_new_client = self.f5connect.tm.ltm.profile.client_ssls.client_ssl.create(
                    partition="Common",
                    name=clientSslProfileName,
                    cert=systemSSLPath,
                    key=systemSSLPath
                )
                self.flagClientSslProfileCreated = True
            else:
                msg = f"Client SSL Profile with name {clientSslProfileName} already exist"
                raise CustomException(msg, code=409)

            create_authz(self.headers["username"], clientSslProfileName)

        except CustomException as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagClientSslProfileCreated:
                deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
                delete_authz(self.headers["username"], clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], systemSslName)

            self.status = 'ERROR'
            self.message = error.message
            self.code = error.code
            return

        except Exception as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagClientSslProfileCreated:
                deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
                delete_authz(self.headers["username"], clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], systemSslName)

            self.status = 'ERROR'
            self.message = "ERROR on Create Certificate - Creating Local Client SSL Profile. " + \
                str(error)
            self.code = 500
            return

        ###########################################
        try:    # Creating Local Server SSL Profile
            print("Creating Local Server SSL Profile")
            self.flagServerSslProfileCreated = False

            systemSSLPath = "/Common/" + systemSslName

            serverSslProfileName = 'serverssl_' + \
                self.parsedParameters_dict["fqdn"]

            all_local_server_ssl = self.f5connect.tm.ltm.profile.server_ssls.get_collection()
            existing_local_server_ssl = [
                server.name for server in all_local_server_ssl]

            if serverSslProfileName not in existing_local_server_ssl:
                ssl_new_server = self.f5connect.tm.ltm.profile.server_ssls.server_ssl.create(
                    partition="Common",
                    name=serverSslProfileName,
                    cert=systemSSLPath,
                    key=systemSSLPath
                )
                self.flagServerSslProfileCreated = True
            else:
                msg = f"Server SSL Profile with name {serverSslProfileName} already exist"
                raise CustomException(msg, code=409)

            create_authz(self.headers["username"], serverSslProfileName)

        except CustomException as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagServerSslProfileCreated:
                deleteLocalServerSslProfile(self.f5connect, serverSslProfileName)
                delete_authz(self.headers["username"], serverSslProfileName)
            deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], clientSslProfileName)
            delete_authz(self.headers["username"], systemSslName)

            self.status = 'ERROR'
            self.message = error.message
            self.code = error.code
            return

        except Exception as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagServerSslProfileCreated:
                deleteLocalServerSslProfile(self.f5connect, serverSslProfileName)
                delete_authz(self.headers["username"], serverSslProfileName)
            deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], clientSslProfileName)
            delete_authz(self.headers["username"], systemSslName)

            self.status = 'ERROR'
            self.message = "ERROR on Create Certificate - Creating Local Server SSL Profile. " + \
                str(error)
            self.code = 500
            return

        ###########################################
        try:    # Creating Client SSL Profile in VIP1
            print("Creating Client SSL Profile in VIP1")
            self.flagClientSslProfileVip1Created = False

            vip1_obj = self.f5connect.tm.ltm.virtuals.virtual.load(
                partition='Common', name=self.vipName)

            all_vip1_ssl_profiles = vip1_obj.profiles_s.get_collection()
            existing_vip1_profiles = [
                profile.name for profile in all_vip1_ssl_profiles]

            if clientSslProfileName not in existing_vip1_profiles:
                vip1_client_new_profile = vip1_obj.profiles_s.profiles.create(
                    partition='Common', name=clientSslProfileName)
                self.flagClientSslProfileVip1Created = True
            else:
                msg = f"Client SSL Profile with name {clientSslProfileName} already exist on VIP1."
                raise CustomException(msg, code=409)

        except CustomException as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagClientSslProfileVip1Created:
                deleteClientSslProfileVip(self.f5connect, clientSslProfileName, self.vipName)
            deleteLocalServerSslProfile(self.f5connect, serverSslProfileName)
            deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], serverSslProfileName)
            delete_authz(self.headers["username"], clientSslProfileName)
            delete_authz(self.headers["username"], systemSslName)
            self.status = 'ERROR'
            self.message = error.message
            self.code = error.code
            return

        except Exception as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagClientSslProfileVip1Created:
                deleteClientSslProfileVip(self.f5connect, clientSslProfileName, self.vipName)
            deleteLocalServerSslProfile(self.f5connect, serverSslProfileName)
            deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], serverSslProfileName)
            delete_authz(self.headers["username"], clientSslProfileName)
            delete_authz(self.headers["username"], systemSslName)

            self.status = 'ERROR'
            self.message = "ERROR on Create Certificate - Creating Client SSL Profile on VIP1. " + \
                str(error)
            self.code = 500
            return

        ###########################################
        try:    # Creating Server SSL Profile in VIP1 if ssl_terminate_f5=no

            self.flagServerSslProfileVip1Created = False
            if self.parsedParameters_dict["ssl_terminate_f5"] == "no":
                print("Creating Server SSL Profile in VIP1 if ssl_terminate_f5=no")
                vip1_obj = self.f5connect.tm.ltm.virtuals.virtual.load(
                    partition='Common', name=self.vipName)

                all_vip1_ssl_profiles = vip1_obj.profiles_s.get_collection()
                existing_vip1_profiles = [
                    profile.name for profile in all_vip1_ssl_profiles]

                if serverSslProfileName not in existing_vip1_profiles:
                    vip1_server_new_profile = vip1_obj.profiles_s.profiles.create(
                        partition='Common', name=serverSslProfileName)
                    self.flagServerSslProfileVip1Created = True
                else:
                    msg = f"Server SSL Profile with name {serverSslProfileName} already exist on VIP1."
                    raise CustomException(msg, code=409)

        except CustomException as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagServerSslProfileVip1Created:
                deleteServerSslProfileVip(self.f5connect, serverSslProfileName, self.vipName)
            deleteClientSslProfileVip(self.f5connect, clientSslProfileName, self.vipName)
            deleteLocalServerSslProfile(self.f5connect, serverSslProfileName)
            deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], serverSslProfileName)
            delete_authz(self.headers["username"], clientSslProfileName)
            delete_authz(self.headers["username"], systemSslName)
            self.status = 'ERROR'
            self.message = error.message
            self.code = error.code
            return

        except Exception as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagServerSslProfileVip1Created:
                deleteServerSslProfileVip(self.f5connect, serverSslProfileName, self.vipName)
            deleteClientSslProfileVip(self.f5connect, clientSslProfileName, self.vipName)
            deleteLocalServerSslProfile(self.f5connect, serverSslProfileName)
            deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], serverSslProfileName)
            delete_authz(self.headers["username"], clientSslProfileName)
            delete_authz(self.headers["username"], systemSslName)
            self.status = 'ERROR'
            self.message = "ERROR on Create Certificate - Creating Client SSL Profile on VIP1. " + \
                str(error)
            self.code = 500
            return

        ###########################################
        try:    # Creating Client SSL Profile in VIP2 if cloud_provider=azure
            self.flagClientSslProfileVip2Created = False
            if self.parsedParameters_dict["cloud_provider"] == "azure":
                print(
                    "ON Creating Client SSL Profile in VIP2 given cloud_provider=azure")

                flag_HA_available = False  # This is temporal as for testing we don't have F5s on HA
                if flag_HA_available:
                    vip2_obj = self.f5connect2.tm.ltm.virtuals.virtual.load(
                        partition='Common', name=self.vipName)

                    all_vip2_ssl_profiles = vip2_obj.profiles_s.get_collection()
                    existing_vip2_profiles = [
                        profile.name for profile in all_vip2_ssl_profiles]

                    if clientSslProfileName not in existing_vip2_profiles:
                        vip2_client_new_profile = vip2_obj.profiles_s.profiles.create(
                            partition='Common', name=clientSslProfileName)
                        self.flagClientSslProfileVip2Created = True
                    else:
                        msg = f"Client SSL Profile with name {clientSslProfileName} already exist on VIP2."
                        raise CustomException(msg, code=409)

        except CustomException as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagClientSslProfileVip2Created:
                deleteClientSslProfileVip(self.f5connect2, clientSslProfileName, self.vipName)
            deleteServerSslProfileVip(self.f5connect, serverSslProfileName, self.vipName)
            deleteClientSslProfileVip(self.f5connect, clientSslProfileName, self.vipName)
            deleteLocalServerSslProfile(self.f5connect, serverSslProfileName)
            deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], serverSslProfileName)
            delete_authz(self.headers["username"], clientSslProfileName)
            delete_authz(self.headers["username"], systemSslName)
            self.status = 'ERROR'
            self.message = error.message
            self.code = error.code
            return

        except Exception as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagClientSslProfileVip2Created:
                deleteClientSslProfileVip(self.f5connect2, clientSslProfileName, self.vipName)
            deleteServerSslProfileVip(self.f5connect, serverSslProfileName, self.vipName)
            deleteClientSslProfileVip(self.f5connect, clientSslProfileName, self.vipName)
            deleteLocalServerSslProfile(self.f5connect, serverSslProfileName)
            deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], serverSslProfileName)
            delete_authz(self.headers["username"], clientSslProfileName)
            delete_authz(self.headers["username"], systemSslName)
            self.status = 'ERROR'
            self.message = "ERROR on Create Certificate - Creating Client SSL Profile on VIP2. " + \
                str(error)
            self.code = 500
            return

        ###########################################
        try:    # Creating Server SSL Profile in VIP2 if cloud_provider=azure and ssl_terminate_f5=no
            self.flagServerSslProfileVip2Created = False
            if (self.parsedParameters_dict["cloud_provider"] == "azure") and (self.parsedParameters_dict["ssl_terminate_f5"] == "no"):
                print(
                    "ON Creating Server SSL Profile in VIP2 given cloud_provider=azure and ssl_terminate_f5=no")

                flag_HA_available = False  # This is temporal as for testing we don't have F5s on HA
                if flag_HA_available:
                    vip2_obj = self.f5connect2.tm.ltm.virtuals.virtual.load(
                        partition='Common', name=self.vipName)

                    all_vip2_ssl_profiles = vip2_obj.profiles_s.get_collection()
                    existing_vip2_profiles = [
                        profile.name for profile in all_vip2_ssl_profiles]

                    if serverSslProfileName not in existing_vip2_profiles:
                        vip2_server_new_profile = vip2_obj.profiles_s.profiles.create(
                            partition='Common', name=serverSslProfileName)
                        self.flagServerSslProfileVip2Created = True
                    else:
                        msg = f"Server SSL Profile with name {serverSslProfileName} already exist on VIP2."
                        raise CustomException(msg, code=409)

        except CustomException as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagServerSslProfileVip2Created:
                deleteServerSslProfileVip(self.f5connect2, serverSslProfileName, self.vipName)
            deleteClientSslProfileVip(self.f5connect2, clientSslProfileName, self.vipName)
            deleteServerSslProfileVip(self.f5connect, serverSslProfileName, self.vipName)
            deleteClientSslProfileVip(self.f5connect, clientSslProfileName, self.vipName)
            deleteLocalServerSslProfile(self.f5connect, serverSslProfileName)
            deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], serverSslProfileName)
            delete_authz(self.headers["username"], clientSslProfileName)
            delete_authz(self.headers["username"], systemSslName)
            self.status = 'ERROR'
            self.message = error.message
            self.code = error.code
            return

        except Exception as error:
            print(error)
            # DELETE PREVIOSLY CREATED RESOURCES
            if self.flagServerSslProfileVip2Created:
                deleteServerSslProfileVip(self.f5connect2, serverSslProfileName, self.vipName)
            deleteClientSslProfileVip(self.f5connect2, clientSslProfileName, self.vipName)
            deleteServerSslProfileVip(self.f5connect, serverSslProfileName, self.vipName)
            deleteClientSslProfileVip(self.f5connect, clientSslProfileName, self.vipName)
            deleteLocalServerSslProfile(self.f5connect, serverSslProfileName)
            deleteLocalClientSslProfile(self.f5connect, clientSslProfileName)
            deleteSystemSsl(self.f5connect, systemSslName)
            delete_authz(self.headers["username"], serverSslProfileName)
            delete_authz(self.headers["username"], clientSslProfileName)
            delete_authz(self.headers["username"], systemSslName)

            self.status = 'ERROR'
            self.message = "ERROR on Create Certificate - Creating Server SSL Profile on VIP2. " + \
                str(error)
            self.code = 500
            return


        self.status = "SUCCESS"
        self.message = "Certificated Created"
        self.code = 200


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


if __name__ == '__main__':
    pass
