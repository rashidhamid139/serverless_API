"""Test Module for UpdateIRule Class.

This will test for all Member Modules

"""
import os
import sys
import json
import unittest
serverless_path = os.getcwd().split("tests")[0] + "/serverless/"
sys.path.append(serverless_path)
from  f5loadbalancer.common.exceptions import CustomException
from f5loadbalancer.irules.update_irule import UpdateIRule
from f5loadbalancer.irules.factory_generator import IRules
from tests.response_objects import *

response_object = {
    'parsed_parameters_object': {"cloud_provider": "aws", "region": "us-east-1", "environment": "dev", "ticket_number": "test-ticket-123", "tcp_upload": "yes", "ssl_terminate_f5": "no", "fqdn": "first.app.deloitte.com", "health_monitor": "https", "load_balancing_method": "round-robin", "members": json.dumps({"members": [{"ip": "100.100.100.1", "port": "443", "status": "enabled"}, {"ip": "100.100.100.2", "port": "443", "status": "disabled"}]}), "f5_ips": "", "vip_name": "", "key_file": "uploaded-file-key-1607163169.key", "cert_file": "uploaded-file-cert-1607163169.crt", "file_path_key": "/tmp/uploaded-file-key-1607163169.key", "file_path_cert": "/tmp/uploaded-file-cert-1607163169.crt", "username": "rasdar@delloitte.com", "pool_name": ""}
}


class Test_UpdateIrule_class_functionality(unittest.TestCase):

    """ This test is for checking initialization of UpdateIRule class"""
    def test_updateirule_initialization(self):
        result_obj = UpdateIRule( {}, {}, {}, json.dumps(response_object['parsed_parameters_object'] ) )
        self.assertEqual(result_obj.body, {})

    def test_updateirule_validate_functionality(self):
        result_obj = UpdateIRule( {}, {}, {}, json.dumps(response_object['parsed_parameters_object'] ) )
        result_obj.validate()
        self.assertEqual(result_obj.status, "SUCCESS")
        self.assertEqual(result_obj.parsedParameters_dict["pool_name"], result_obj.parsedParameters_dict["fqdn"]+"_443")

    def test_updateirule_validateF5IPInput_functionality(self):
        result_obj = UpdateIRule( {}, {}, {}, json.dumps(response_object['parsed_parameters_object'] ) )
        result = result_obj.validateF5IPInput()
        self.assertEqual(result[0], "Empty f5_ips List")
        self.assertEqual( result[1], False )
        # result = result_obj.validateF5IPInput()

class Test_IRule_class_functionality(unittest.TestCase):
    """ This test is for checking initiliazation of IRule class"""
    def test_irule_initialiazation(self):
        result_obj = IRules( "GET", {}, {}, {}, json.dumps(response_object['parsed_parameters_object']) )
        self.assertEqual(result_obj.method, "GET")
        self.assertEqual( result_obj.body, {} )
        self.assertEqual( result_obj.parsedParameters, json.dumps(response_object['parsed_parameters_object']))

    """ This test is to check whether an exception is raised properly when wrong method is used"""
    def test_irule_operation_method(self):
        result_obj = IRules( "GET", {}, {}, {}, json.dumps(response_object['parsed_parameters_object']) )
        self.assertRaises(CustomException, result_obj.operation)


if __name__ == '__main__':
    unittest.main()