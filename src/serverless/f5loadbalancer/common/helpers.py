import re
import os
import json
from f5.bigip import ManagementRoot
from .exceptions import CustomException
from .authz import create_authz, delete_authz


def deleteSystemSsl(f5connect, systemSslName):
    print("On deleteSystemSsl")
    print(systemSslName)

    try:
        all_system_ssl_certs = f5connect.tm.sys.file.ssl_certs.get_collection()
        existing_system_ssl_certs = [
            cert.name for cert in all_system_ssl_certs]

        if systemSslName in existing_system_ssl_certs:
            try:
                system_cert_todelete = f5connect.tm.sys.file.ssl_certs.ssl_cert.load(
                    name=systemSslName)
                system_cert_todelete.delete()
            except:
                print("It was not possible delete the System SSL Cert")

        all_system_ssl_keys = f5connect.tm.sys.file.ssl_keys.get_collection()
        existing_system_ssl_keys = [key.name for key in all_system_ssl_keys]

        if systemSslName in existing_system_ssl_keys:
            try:
                system_key_todelete = f5connect.tm.sys.file.ssl_keys.ssl_key.load(
                    name=systemSslName)
                system_key_todelete.delete()
            except:
                print("It was not possible delete the System SSL Key")
    except:
        pass


def deleteLocalClientSslProfile(f5connect, clientSslProfileName):
    print("On deleteLocalClientSslProfile")
    print(clientSslProfileName)

    try:
        all_local_client_ssl = f5connect.tm.ltm.profile.client_ssls.get_collection()
        existing_local_client_ssl = [
            client.name for client in all_local_client_ssl]

        if clientSslProfileName in existing_local_client_ssl:
            try:
                local_ssl_client_todelete = f5connect.tm.ltm.profile.client_ssls.client_ssl.load(
                    name=clientSslProfileName
                )
                local_ssl_client_todelete.delete()
            except:
                print("It was not possible delete the Client SSL Profile")
    except:
        pass


def deleteLocalServerSslProfile(f5connect, serverSslProfileName):
    print("On deleteLocalServerSslProfile")
    print(serverSslProfileName)

    try:
        all_local_server_ssl = f5connect.tm.ltm.profile.server_ssls.get_collection()
        existing_local_server_ssl = [
            server.name for server in all_local_server_ssl]

        if serverSslProfileName in existing_local_server_ssl:
            try:
                local_ssl_server_todelete = f5connect.tm.ltm.profile.server_ssls.server_ssl.load(
                    name=serverSslProfileName
                )
                local_ssl_server_todelete.delete()
            except:
                print("It was not possible delete the Server SSL Profile")
    except:
        pass


def deleteClientSslProfileVip(f5connect, clientSslProfileName, vipName):
    print("On deleteClientSslProfileVip")
    print(clientSslProfileName)

    try:
        vip_obj = f5connect.tm.ltm.virtuals.virtual.load(
            partition='Common', name=vipName)

        all_vip_ssl_profiles = vip_obj.profiles_s.get_collection()
        existing_vip_profiles = [
            profile.name for profile in all_vip_ssl_profiles]

        if clientSslProfileName in existing_vip_profiles:
            try:
                vip_profile_todelete = vip_obj.profiles_s.profiles.load(
                    partition='Common', name=clientSslProfileName)
                vip_profile_todelete.delete()
            except:
                print("It was not possible delete the Client SSL Profile from VIP")
    except:
        pass


def deleteServerSslProfileVip(f5connect, serverSslProfileName, vipName):
    print("On deleteServerSslProfileVip")
    print(serverSslProfileName)

    try:
        vip_obj = f5connect.tm.ltm.virtuals.virtual.load(
            partition='Common', name=vipName)

        all_vip_ssl_profiles = vip_obj.profiles_s.get_collection()
        existing_vip_profiles = [
            profile.name for profile in all_vip_ssl_profiles]

        if serverSslProfileName in existing_vip_profiles:
            try:
                vip_profile_todelete = vip_obj.profiles_s.profiles.load(
                    partition='Common', name=serverSslProfileName)
                vip_profile_todelete.delete()
            except:
                print("It was not possible delete the Server SSL Profile from VIP")
    except:
        pass


def deleteCertificateALLHelper(f5connect, f5connect2, vipName, cloud_provider, ssl_terminate_f5, fqdn, user_name):

    print("On deleteCertificateALLHelper")

    try:
        systemSslName = 'ssl_' + fqdn
        clientSslProfileName = 'clientssl_' + fqdn
        serverSslProfileName = 'serverssl_' + fqdn

        if (cloud_provider == "azure") and (ssl_terminate_f5 == "no"):
            print("On deleteServerSslProfileVip for VIP2 on F52")
            flag_HA_available = False  # This is temporal as for testing we don't have F5s on HA
            if flag_HA_available:
                deleteServerSslProfileVip(
                    f5connect2, serverSslProfileName, vipName)

        if cloud_provider == "azure":
            print("On deleteClientSslProfileVip for VIP2 on F52")
            flag_HA_available = False  # This is temporal as for testing we don't have F5s on HA
            if flag_HA_available:
                deleteClientSslProfileVip(
                    f5connect2, clientSslProfileName, vipName)

        if ssl_terminate_f5 == "no":
            #deleteLocalServerSslProfile(f5connect, serverSslProfileName)
            deleteServerSslProfileVip(f5connect, serverSslProfileName, vipName)

        deleteClientSslProfileVip(f5connect, clientSslProfileName, vipName)
        deleteLocalServerSslProfile(f5connect, serverSslProfileName)
        deleteLocalClientSslProfile(f5connect, clientSslProfileName)
        deleteSystemSsl(f5connect, systemSslName)
        delete_authz(user_name, serverSslProfileName)
        delete_authz(user_name, clientSslProfileName)
        delete_authz(user_name, systemSslName)
    except:
        pass


def deletePollAndMembersHelper(f5connect, pool_name, user_name):

    print("On deletePollAndMembersHelper")

    try:
        if f5connect.tm.ltm.pools.pool.exists(name=pool_name, partition='Common'):
            pool_obj = f5connect.tm.ltm.pools.pool.load(
                partition='Common', name=pool_name)
            members_list = pool_obj.members_s.get_collection()
            for member in members_list:
                member_obj = pool_obj.members_s.members.load(
                    partition='Common', name=member.name)
                member_obj.delete()
                node_name = member.name.split(":")[0]
                if (f5connect.tm.ltm.nodes.node.exists(partition='Common', name=node_name)):
                    node_obj = f5connect.tm.ltm.nodes.node.load(
                        partition='Common', name=node_name)
                    try:
                        node_obj.delete()
                    except:
                        pass
            pool_obj.delete()

        delete_authz(user_name, pool_name)
        print("reverted_CreatePool")
    except:
        pass


def undoUpdateIRuleHelper(f5connect, vipName, fqdn, user_name):

    print("On undoUpdateIRuleHelper")

    try:
        vip_redirect = f5connect.tm.ltm.virtuals.virtual.load(
            partition='Common', name=vipName)
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
            redirect_irule_name=irulefrag[2]
            redirect_irule = f5connect.tm.ltm.rules.rule.load(
                name=irulefrag[2],
                partition=irulefrag[1]
            )
        else:
            msg = "There is more than one redirect irule on the VIP."
            raise CustomException(msg, code=400)

        if fqdn not in redirect_irule.raw["apiAnonymous"]:
            msg = "The IRULE does not contains the fqdn."
            raise CustomException(msg, code=400)
        else:
            irule_groups = redirect_irule.raw["apiAnonymous"].split('{')
            irule_section_1 = '{'.join(irule_groups[:2]) + "{"
            irule_section_2 = '{'.join(irule_groups[2:])

            irule2_groups = irule_section_2.split('}')
            irule2_section_2 = '}'.join(irule2_groups[1:])
            reverted_irule = irule_section_1 + irule2_section_2

            redirect_irule.update(apiAnonymous=reverted_irule)

            #Authorization record creation in AuthZ was deactivate for Irules
            #delete_authz(user_name, redirect_irule_name)

            print("reverted_irule")
            print(reverted_irule)
    except:
        pass


if __name__ == '__main__':
    pass
