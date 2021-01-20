import os
import sys
import pytest
import requests
serverless_path = os.getcwd().split("tests")[0] + "serverless/"
sys.path.append(serverless_path)
from mock import Mock
from requests import Timeout
from f5loadbalancer.common.helpers import ( deleteSystemSsl, deleteLocalClientSslProfile, deleteLocalServerSslProfile, deleteClientSslProfileVip,
deleteServerSslProfileVip, deleteCertificateALLHelper, deletePollAndMembersHelper, undoUpdateIRuleHelper)