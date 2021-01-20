"""Test Module for Certificate Class.

This will test for all Member Modules

"""
import os, time
import pytest
import sys
import json
import unittest
from unittest import mock
serverless_path = os.getcwd().split("tests")[0] + "/serverless/"
sys.path.append(serverless_path)
sys.path.insert(0,'../')
from unittest.mock import patch, Mock
from f5loadbalancer.certificates.create_certificate import CreateCert
from f5loadbalancer.common.exceptions import CustomException
from f5loadbalancer.certificates.factory_generator  import Certificates
from tests.response_objects import *



class Test_Certificates(unittest.TestCase):
    def setUp(self):
        self.method = "POST"
        self.headers = headers_object
        self.body = body_object
        self.queryparams = {}
        self.parsedParameters = parsed_parameters

    '''This test checks Initilization of Certificates class'''
    def test_Certificates_class_initialiazation(self):
        certificate_object = Certificates(self.method, self.body, self.headers, self.queryparams, json.dumps(self.parsedParameters))
        self.assertEqual( self.method, "POST")
        self.method = "GET"
        certificate_object = Certificates(self.method, self.body, self.headers, self.queryparams, json.dumps(self.parsedParameters))
        self.assertRaises(CustomException, certificate_object.operation )
        certificate_object = Certificates(self.method, self.body, self.headers, self.queryparams, json.dumps(self.parsedParameters))

    def tearDown(self):
        del self

