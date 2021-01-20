import os
import sys
import pytest
import unittest
from unittest import mock
serverless_path = os.getcwd().split("tests")[0] + "/serverless/"
sys.path.append(serverless_path)
from unittest.mock import Mock, patch
from f5loadbalancer.common.connections import (ParseYaml, get_secret, getF5IPs )
from f5loadbalancer.common.exceptions import CustomException




class Test_Connection_Class_functionality(unittest.TestCase ):
    def test_get_F5IP_functionality(self):
        self.assertRaises(CustomException, getF5IPs,"us-east-1", "yes", "aws", "dev" )
        self.assertRaises( CustomException, getF5IPs, "us-east-1", "no", 567, "677")

    def test_ParseYaml_class_functionality(self):
        result_obj = ParseYaml("us-east-1", "yes", "dev", "azure")
        self.assertEqual( result_obj.provider, "azure")

    @mock.patch( 'f5loadbalancer.common.connections.ParseYaml.read_input_file')
    def test_ParseYaml_class_readInputFile(self, mock_read_input_file):
        result_obj = ParseYaml("us-east-1", "yes", "dev", "azure")
        self.assertEqual( result_obj.provider, "azure")
        # self.assertRaises(CustomException, result_obj.read_input_file,  )

    def test_get_ParseYaml_class_dev_functionality(self):
        parse_yaml_obj = ParseYaml('us-east-1', 'yes', 'dev', 'aws')
        with open( 'f5-mapping-stage.yml', 'r') as bucket_content:
            file_content = bucket_content.read()

        result = parse_yaml_obj.read_input_file( file_content )
        self.assertEqual( len( result ), 5 )
        self.assertEqual( result[0], '107.22.214.8')
        self.assertEqual( result[4], 'vz_usazsubemaeuwhub-pip-npd_1481' )

    def test_get_ParseYaml_class_stage_functionality(self):
        parse_yaml_obj = ParseYaml('us-east-1', 'yes', 'stage', 'aws')
        with open( 'f5-mapping-stage.yml', 'r') as bucket_content:
            file_content = bucket_content.read()

        result = parse_yaml_obj.read_input_file( file_content )
        self.assertEqual( len( result ), 5 )
        self.assertEqual( result[0], '107.22.214.8')
        self.assertEqual( result[4], 'vz_usazsubemaeuwhub-pip-npd_1482' )

    def test_get_ParseYaml_class_prod_functionality(self):
        parse_yaml_obj = ParseYaml('us-east-1', 'yes', 'prod', 'aws')
        with open( 'f5-mapping-stage.yml', 'r') as bucket_content:
            file_content = bucket_content.read()

        result = parse_yaml_obj.read_input_file( file_content )
        self.assertEqual( len( result ), 5 )
        self.assertEqual( result[0], '107.22.214.8')
        self.assertEqual( result[4], 'vz_usazsubemaeuwhub-pip-npd_1483' )

    @mock.patch( "f5loadbalancer.common.connections.os.environ")
    def rtest_get_secret_functionality(self, mock_os_environ ):
        string_argument = "String_Input"
        integer_argument = 123456
        mock_os_environ.return_value.SECRET_MANAGER_ID = 'test_secret'
        # result = get_secret( "192.10.1.0")
        self.assertRaises(CustomException, get_secret, string_argument)
        self.assertRaises(CustomException, get_secret, integer_argument)

if __name__ == '__main__':
    unittest.main()