"""Test Module for CreatePool Class.

This will test for all Member Modules

"""
import os
import sys
import json
import unittest
serverless_path = os.getcwd().split("tests")[0] + "/serverless/"
sys.path.append(serverless_path)
from unittest.mock import Mock, patch
from f5loadbalancer.common.exceptions import CustomException
from f5loadbalancer.pools.create_pool import CreatePool
from f5loadbalancer.pools.factory_generator import Pools
from tests.response_objects import *


parsed_parameters = {"cloud_provider": "aws", "region": "us-east-1", "environment": "dev", "ticket_number": "test-ticket-123", "tcp_upload": "yes", "ssl_terminate_f5": "no", "fqdn": "first.app.deloitte.com", "health_monitor": "https", "load_balancing_method": "round-robin", "members": json.dumps({"members": [{"ip": "100.100.100.1", "port": "443", "status": "enabled"}, {"ip": "100.100.100.2", "port": "443", "status": "disabled"}]}), "f5_ips": "", "vip_name": "", "key_file": "uploaded-file-key-1607163169.key", "cert_file": "uploaded-file-cert-1607163169.crt", "file_path_key": "uploaded-file-key-1607163169.key", "file_path_cert": "uploaded-file-cert-1607163169.crt", "username": "rasdar@delloitte.com", "pool_name": ""}

headers_object = {
    'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate, br', 'Cache-Control': 'no-cache', 'CloudFront-Forwarded-Proto': 'https', 'CloudFront-Is-Desktop-Viewer': 'true', 'CloudFront-Is-Mobile-Viewer': 'false', 'CloudFront-Is-SmartTV-Viewer': 'false', 'CloudFront-Is-Tablet-Viewer': 'false', 'CloudFront-Viewer-Country': 'US', 'content-type': 'multipart/form-data; boundary=--------------------------381636933030506020173192', 'Host': '0cejeiswsk.execute-api.us-east-1.amazonaws.com', 'Postman-Token': '5b0d4893-1b27-442d-bb2c-cd29ef6211d6', 'User-Agent': 'PostmanRuntime/7.26.5', 'Via': '1.1 1e357724bdb0ea3eaba680124ea9eacb.cloudfront.net (CloudFront)', 'X-Amz-Cf-Id': '1y6rVskT46SmMkh1fU7PvDm_zy5FyPoFQm-ouV2DzBtB5uBFfhWMnA==', 'X-Amzn-Trace-Id': 'Root=1-5f97872e-094f49eb218f5d873d5b12d5', 'x-api-key': 'n6GgdSSeCb29uqQUZZiPy5j3dK5ZkCFnaxLSVevp', 'X-Forwarded-For': '24.30.108.230, 64.252.176.69', 'X-Forwarded-Port': '443', 'X-Forwarded-Proto': 'https'
}
member_object = {"members": [{"ip": "100.100.100.1", "port": "443", "status": "enabled"}, {"ip": "100.100.100.2", "port": "443", "status": "disabled"}]}

class Test_CreatePool_class_functionality(unittest.TestCase):
    """This test is used for checking CreatePool class"""
    def test_create_pool_initialization(self):
        result_obj = CreatePool( body_object, headers_object, {}, json.dumps(parsed_parameters ) )
        self.assertEqual( len(result_obj.headers)>0, True )
        self.assertEqual( type(result_obj.headers), dict )
        self.assertEqual( hasattr(result_obj, 'parsedParameters'), True)

    """This test is used for checking validate functionality of CreatePool class"""
    def test_create_pool_validate_functionality(self):
        result_obj = CreatePool( body_object, headers_object, {}, json.dumps(parsed_parameters ) )
        result_obj.validate()
        self.assertEqual(result_obj.status, "SUCCESS")
        self.assertEqual(result_obj.parsedParameters_dict["pool_name"], result_obj.parsedParameters_dict["fqdn"]+"_443")
        del(result_obj.parsedParameters_dict['pool_name'])
        self.assertEqual(hasattr( result_obj.parsedParameters_dict, "pool_name"), False )

    def stest_create_pool_validateMemberInput_functionality(self):
        result_obj = CreatePool( {}, {}, {}, json.dumps(parsed_parameters ) )
        result = result_obj.validateMemberInput()
        self.assertEqual(result[0], "Empty Member List")
        self.assertEqual( result[1], False )

    def test_create_pool_validateF5IPInput_functionality(self):
        result_obj = CreatePool( {}, {}, {}, json.dumps(parsed_parameters ) )
        result = result_obj.validateF5IPInput()
        self.assertEqual(result[0], "Empty f5_ips List")
        self.assertEqual( result[1], False )

    def test_create_pool_functionality(self):
        result_obj = CreatePool( {}, {}, {}, json.dumps(parsed_parameters ) )
        self.assertRaises(CustomException, result_obj.createPool )

    def test_create_pool_addmember_functionality(self):
        result_obj = CreatePool( {}, {}, {}, json.dumps(parsed_parameters ) )
        self.assertRaises( CustomException, result_obj.addMembers , "test_poolname_1", {})


class Test_Pools_class_functionality(unittest.TestCase):
    """ This test is for checking initiliazation of IRule class"""
    def test_pools_initialiazation(self):
        result_obj = Pools( "GET", {}, {}, {}, json.dumps(parsed_parameters) )
        self.assertEqual(result_obj.method, "GET")
        self.assertEqual( result_obj.body, {} )
        self.assertEqual( result_obj.parsedParameters, json.dumps(parsed_parameters))

    """ This test is to check whether an exception is raised properly when wrong method is used"""
    def test_irule_operation_method(self):
        result_obj = Pools( "GET", {}, {}, {}, json.dumps(parsed_parameters) )
        self.assertRaises(CustomException, result_obj.operation)



if __name__ == '__main__':
    unittest.main()