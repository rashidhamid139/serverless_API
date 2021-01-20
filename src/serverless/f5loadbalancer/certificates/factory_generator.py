#!/usr/bin/venv python3
from .create_certificate import CreateCert
from ..common.exceptions import CustomException

class Certificates:

    def __init__(self, method, body, headers, queryparams, parsedParameters, **kwargs):
        self.method = method
        self.body = body
        self.headers = headers
        self.queryparams =queryparams
        self.parsedParameters = parsedParameters
        self.__dict__.update(kwargs)
        self.extra_params = kwargs

    def operation(self):
        if self.method == 'POST':
            print("On operation Certificates")
            return CreateCert(body=self.body, headers=self.headers, queryparams=self.queryparams, parsedParameters=self.parsedParameters, extra_params=self.extra_params)
        else:
            msg = 'Invalid HTTP Method ' + self.method + ' for the endpoint.'
            raise CustomException(msg, code=405)


if __name__ == '__main__':
    pass
