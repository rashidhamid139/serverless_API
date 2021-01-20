#!/usr/bin/venv python3

from abc import ABC, abstractmethod


class BaseOperations(ABC):
    """Class to create Objects based on variables passed."""

    def __init__(self, *arg, **kwarg):

        self.f5connect = None
        self.status = "ERROR"
        self.code = 500
        self.message = "Internal Server Error"


        if hasattr(self, 'extra_params'):
            for keys , values in self.extra_params.items():
                setattr(self, keys, values)


    @abstractmethod
    def operate(self):
        """Abstract Method for defining Operations of Member Class."""

    @abstractmethod
    def validate(self):
        """Abstract Method for defining
        validation operation for Member class."""

    def run(self):
        """Inherited Method to be used by all derivatives
        of this base class."""
        self.validate()
        if self.status == "SUCCESS":
            self.operate()


if __name__ == '__main__':
    pass
