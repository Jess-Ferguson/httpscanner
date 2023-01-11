# exceptions.py - Exception classes related to the HTTPScanner package

class HTTPScannerException(Exception):
    """ Base class for exceptions related to HTTPScanner internals """
    pass


class InvalidTimeoutError(HTTPScannerException):
    """ Raised when the timeout value is invalid """
    pass


class InvalidRetriesError(HTTPScannerException):
    """ Raised when the number of retries is invalid """
    pass


class InvalidNumOfThreadsError(HTTPScannerException):
    """ Raised when the number of threads given is invalid """
    pass


class AnalysisError(HTTPScannerException):
    """ Raised when the site could not be analysed """
    pass