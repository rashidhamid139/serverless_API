#!/usr/bin/venv python3
class CustomException(Exception):
    def __init__(self, message, *args, **kwargs):
        self.code = kwargs['code']
        self.message = message
        pass
