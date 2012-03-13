import logging
import socket

from .packages.ssl_match_hostname import match_hostname, CertificateError
from .packages import six
from .request import HTTPRequest
from .response import HTTPResponse

## Connection objects
class Connection(object):
    """
    Base class for connections. Patterned after httplib.HTTPConnection but
    designed to be more extensible
    """

    def __init__(self):
        """
        construct a Connection
        """

    def request(self, req, resp=HTTPResponse):
        """
        request data over the connection
        """

class HTTPConnection(Connection):
    """
    Support basic HTTP connection logic
    """
    pass

class HTTPSConnection(HTTPConnection):
    """
    Support basic HTTPS connection logic
    """
    pass

class VerifiedHTTPSConnection(HTTPSConnection):
    """
    Based on httplib.HTTPSConnection but wraps the socket with
    SSL certification.
    """
    cert_reqs = None
    ca_certs = None

    def set_cert(self, key_file=None, cert_file=None,
                 cert_reqs='CERT_NONE', ca_certs=None):
        ssl_req_scheme = {
            'CERT_NONE': ssl.CERT_NONE,
            'CERT_OPTIONAL': ssl.CERT_OPTIONAL,
            'CERT_REQUIRED': ssl.CERT_REQUIRED
        }

        self.key_file = key_file
        self.cert_file = cert_file
        self.cert_reqs = ssl_req_scheme.get(cert_reqs) or ssl.CERT_NONE
        self.ca_certs = ca_certs

    def connect(self):
        # Add certificate verification
        sock = socket.create_connection((self.host, self.port), self.timeout)

        # Wrap socket using verification with the root certs in
        # trusted_root_certs
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                    cert_reqs=self.cert_reqs,
                                    ca_certs=self.ca_certs)
        if self.ca_certs:
            match_hostname(self.sock.getpeercert(), self.host)
