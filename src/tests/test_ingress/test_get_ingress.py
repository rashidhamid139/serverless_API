"""Test Module for CreateIngress Class.

This will test for all Member Modules

"""

import os
import sys
import json
import unittest
serverless_path = os.getcwd().split("tests")[0] + "/serverless/"
sys.path.append(serverless_path)
sys.path.insert(0,'../')
from unittest import mock
from f5loadbalancer.common.exceptions import CustomException
from f5loadbalancer.ingress.factory_generator import Ingress
from f5loadbalancer.ingress.create_ingress import CreateIngress
from tests.response_objects import *


class TestIngressClass(unittest.TestCase):

    def setUp(self):
        self.create_ingress_object = ''
        self.body = body_object
        self.headers = headers_object
        self.queryparams = {}
        self.parsedParameters = json.dumps( parsed_parameters)

    """
    This test is written to make sure an Exception is raised whenever we try to access with Invalid method
    """
    
    def test_InvalidMethod_exception_in_IngressClass(self):
        result_obj = Ingress("GET", self.body, self.headers, {
        }, self.parsedParameters)
        self.assertRaises(CustomException,  result_obj.operation, )

    def test_CreateIngress_Class_Initialization(self):
        create_ingress_obj = CreateIngress(
            {}, {}, {}, {}, {"key1": "", "key2": ""})
        self.assertEqual(create_ingress_obj.body, {})

    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.exists')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.isfile')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.stat')
    def test_create_ingress_validate_method( self, mock_os_stat, mock_os_path_isfile, mock_os_path_exists):
        print("In Validate Method")
        mock_os_path_exists.return_value = True
        mock_os_path_isfile.return_value = True
        mock_os_stat.return_value.st_size = 6
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        create_ingress_obj.validate()
        self.assertEqual( create_ingress_obj.status, "SUCCESS")

    def test_validateMemberInput_method_for_empty_members(self):
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        result = create_ingress_obj.validateMemberInput([])
        self.assertFalse( result[1])

    def test_validateMemberInput_method_for_ip(self):
        member_input = [{'ip': '100.100.10x.1', 'port': '443', 'status': 'enabled'}, {'ip': '100.100.100.2', 'port': '443', 'status': 'disabled'}]
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        result = create_ingress_obj.validateMemberInput(member_input)
        self.assertIn( "Invalid IP for", result[0])
        
    def test_validateMemberInput_method_for_port(self):
        member_input = [{'ip': '100.100.100.1', 'port': '043', 'status': 'enabled'}, {'ip': '100.100.100.2', 'port': '4400003', 'status': 'disabled'}]
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        result = create_ingress_obj.validateMemberInput(member_input)
        self.assertIn( "Invalid member Port", result[0])

    def test_validateMemberInput_method_for_status(self):
        member_input = [{'ip': '100.100.100.1', 'port': '043', 'status': ''}, {'ip': '100.100.100.2', 'port': '4400003', 'status': 'disabled'}]
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        result = create_ingress_obj.validateMemberInput(member_input)
        self.assertIn( "Invalid member status", result[0])

    def test_validateF5IPInput_for_empty_f5ipslist(self):
        
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        result = create_ingress_obj.validateF5IPInput()
        self.assertFalse(result[1])
        f5_ips_list = []
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        result = create_ingress_obj.validateF5IPInput(f5_ips_list)
        self.assertFalse(result[1])
        f5_ips_list = {}
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        result = create_ingress_obj.validateF5IPInput(f5_ips_list)
        self.assertFalse(result[1])


    def test_validateF5IPInput_for_invalid_f5_port(self):
        f5_ips_list = [{'ip': '100.100.100.1', 'port': 'xx443'}, {'ip': '100.100.100.2', 'port': '443'}]
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        result = create_ingress_obj.validateF5IPInput( f5_ips_list)
        self.assertIn("Invalid f5_ips Parameter", result[0])

    def test_validateF5IPInput_for_invalid_f5_ip(self):
        f5_ips_list = [{'ip': '100.100.10b0.1', 'port': '443'}, {'ip': '100.100.100.2', 'port': '443'}]
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        result = create_ingress_obj.validateF5IPInput( f5_ips_list)
        self.assertIn("Invalid IP for", result[0])

    def test_validateF5IPInput_for_valid_f5_ips_list(self):
        f5_ips_list = [{'ip': '100.100.100.1', 'port': '443'}, {'ip': '100.100.100.2', 'port': '443'}]
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        result = create_ingress_obj.validateF5IPInput( f5_ips_list)
        self.assertIn("All Valid f5_ips", result[0])


    ##test create certificate function 

    @mock.patch( 'f5loadbalancer.ingress.create_ingress.mainCertificate')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.exists')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.isfile')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.stat')
    def test_createCert_function(self, mock_os_path, mock_os_path_isfile, mock_os_stat ,mock_createCert):
        mock_createCert.return_value =  {'isBase64Encoded': True, 'statusCode': 200, 'headers': {'content-type': 'application/json'}, 'body': '{"status" : "SUCCESS", "message": "Pool Created Successfully" }'}
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        create_ingress_obj.validate()
        self.assertEqual( create_ingress_obj.status, "SUCCESS")
        create_ingress_obj.createCert()
        self.assertEqual( create_ingress_obj.code, 200)
    

    @mock.patch( 'f5loadbalancer.ingress.create_ingress.mainPool')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.exists')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.isfile')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.stat')
    def test_createPool_function( self, mock_os_stat, mock_os_path_isfile, mock_os_path_exists, mock_mainPool ):
        mock_mainPool.return_value =  {'isBase64Encoded': True, 'statusCode': 200, 'headers': {'content-type': 'application/json'}, 'body': '{"status" : "SUCCESS", "message": "Server Error. IPs, ports and Vip" }'}
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        create_ingress_obj.validate()
        self.assertEqual( create_ingress_obj.status, "SUCCESS")
        create_ingress_obj.createPool()
        self.assertEqual( create_ingress_obj.code, 200)

    @mock.patch( 'f5loadbalancer.ingress.create_ingress.mainPool')
    def test_createPool_function_before_calling_validate_function(self, mock_mainPool):
        mock_mainPool.return_value =   {'isBase64Encoded': True, 'statusCode': 200, 'headers': {'content-type': 'application/json'}, 'body': '{"status" : "SUCCESS", "message": "Server Error. IPs, ports and Vip" }'}
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        create_ingress_obj.createPool()
        self.assertEqual( create_ingress_obj.code , 500)
        self.assertEqual( create_ingress_obj.status, "ERROR")

    @mock.patch( 'f5loadbalancer.ingress.create_ingress.deleteCertificateALLHelper')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.exists')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.isfile')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.stat')
    def test_deleteCertificateAll_function(self, mock_stat, mock_isfile, mock_exists, mock_deleteCertificateALLHelper ):
        mock_deleteCertificateALLHelper.return_value = True
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        create_ingress_obj.validate()
        self.assertEqual( create_ingress_obj.status, "SUCCESS")
        create_ingress_obj.f5connect = True
        create_ingress_obj.f5connect2 = True
        create_ingress_obj.deleteCertificateAll()
        mock_deleteCertificateALLHelper.mock_calls == 1

    @mock.patch( 'f5loadbalancer.ingress.create_ingress.deletePollAndMembersHelper')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.exists')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.isfile')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.stat')
    def test_deletePollAndMembers_function(self, mock_stat, mock_isfile, mock_exists, mock_deletePollAndMembers ):
        mock_deletePollAndMembers.return_value = True
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        create_ingress_obj.validate()
        self.assertEqual( create_ingress_obj.status, "SUCCESS")
        create_ingress_obj.f5connect = True
        create_ingress_obj.f5connect2 = True
        create_ingress_obj.deletePollAndMembers()
        mock_deletePollAndMembers.mock_calls == 1


    @mock.patch( 'f5loadbalancer.ingress.create_ingress.undoUpdateIRuleHelper')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.exists')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.isfile')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.stat')
    def test_undoUpdateIRule_function(self, mock_stat, mock_isfile, mock_exists, mock_undoUpdateIRule ):
        mock_undoUpdateIRule.return_value = True
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        create_ingress_obj.validate()
        self.assertEqual( create_ingress_obj.status, "SUCCESS")
        create_ingress_obj.f5connect = True
        create_ingress_obj.f5connect2 = True
        create_ingress_obj.undoUpdateIRule()
        mock_undoUpdateIRule.mock_calls == 1

    @mock.patch( 'f5loadbalancer.ingress.create_ingress.mainIRule')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.exists')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.path.isfile')
    @mock.patch( 'f5loadbalancer.ingress.create_ingress.os.stat' )
    def test_updateIRule_function(self, mock_stat, mock_isfile, mock_exists, mock_updateIRule ):
        mock_updateIRule.return_value = True
        create_ingress_obj = CreateIngress(self.body, self.headers, {}, self.parsedParameters)
        create_ingress_obj.validate()
        self.assertEqual( create_ingress_obj.status, "SUCCESS")
        create_ingress_obj.f5connect = True
        create_ingress_obj.f5connect2 = True
        create_ingress_obj.updateIRule()
        mock_updateIRule.mock_calls == 1

    def tearDown(self):
        del self.create_ingress_object 


if __name__ == '__main__':
    unittest.main()
