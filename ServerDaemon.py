#!/usr/bin/python
#
# CBNCA RPC SERVER PROCESS
#
# $Id$
#

import threading
import logging
import socket
import select
import string
import time
import types
import sys
import traceback
import os.path
import tempfile
import re
import base64
import math
import pg
import traceback
import uuid
import subprocess

from pprint import PrettyPrinter, pprint
from signal import pause
from StringIO import StringIO

from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from Config import Config
from Errors import *
from CertificateManager import CertificateManager
from AccessControl import AccessControlManager
from M2Crypto.ASN1 import *
import Logging

from M2Crypto import *
from M2Crypto.SMIME import *

from terminal_registration import *

m2.load_nids()

class ServerDaemon(object):

    def __init__(self, config, quiet=False):
        self._config = config
        self.quiet = quiet
        self.halt = False
        self._certificate_managers = {}
        self._access_control_managers = {}

        self._admin_rpc_server_address = self._config.get_admin_rpc_server_address()
        self._admin_rpc_server_port = self._config.get_admin_rpc_server_port()

        self._scep_rpc_server_address = self._config.get_scep_rpc_server_address()
        self._scep_rpc_server_port = self._config.get_scep_rpc_server_port()

        self._spki_rpc_server_address = self._config.get_spki_rpc_server_address()
        self._spki_rpc_server_port = self._config.get_spki_rpc_server_port()

        Logging.initialize(config)
        Logging.initialize_debug(config, 'server')

        self._load_certificate_managers()
        self._load_access_control()

	socket.setdefaulttimeout(120)
        
    def _load_certificate_managers(self):
        ca_list = self._config.get_ca_list()
        
        for ca in ca_list:
            Logging.initialize_debug(self._config, ca)
            self._certificate_managers[ca] = CertificateManager(self._config, ca,
                                                                signature_algorithm=None)
            self._certificate_managers[ca].schedule_regeneration()

    def _load_access_control(self):
        ca_list = self._config.get_ca_list()
        
        server_access_control_method = self._config.get_access_control_method('server')
        Logging.debug(('daemon', '_load_access_control'),
                      'Initializing server access control: %s' % server_access_control_method)
        server_access_parameters = AccessControlManager.parameters(
            server_access_control_method, self._config, 'server')
        server_access_parameters['server-manager'] = True
        
        self._server_access_control_manager = AccessControlManager.factory(
            server_access_control_method, server_access_parameters)
        self._access_control_managers['server'] = self._server_access_control_manager
        
        for ca in ca_list:
            self._add_access_control(ca)

    def _add_access_control(self, ca, permissions={}):
        access_control_method = self._config.get_access_control_method(ca)
        Logging.debug(('daemon', '_add_access_control'),
                      'Initializing authority access control: %s' % access_control_method)
        access_parameters = AccessControlManager.parameters(access_control_method, self._config, ca)
        access_parameters['server-manager'] = self._server_access_control_manager
        self._access_control_managers[ca] = AccessControlManager.factory(access_control_method,
                                                                         access_parameters)
        for (username, level) in permissions.iteritems():
            Logging.debug(('daemon', '_add_access_control'),
                          'adding permissions: %s:%s' % (username, level))
            self._access_control_managers[ca].setAccess(username, level)
            
    def get_certificate_managers(self):
        return self._certificate_managers
            
    def run(self):
        # Start RPC servers for the user-interface and the SCEP management interface
        self._admin_rpc_server = AdminRPCServer(self, quiet=self.quiet,
                                                listen_address=self._admin_rpc_server_address,
                                                listen_port=self._admin_rpc_server_port)
        self._scep_rpc_server = SCEPServer(self, quiet=self.quiet,
                                           listen_address=self._scep_rpc_server_address,
                                           listen_port=self._scep_rpc_server_port)
        self._spki_rpc_server = SPKIServer(self, quiet=self.quiet,
                                           listen_address=self._spki_rpc_server_address,
                                           listen_port=self._spki_rpc_server_port)

        # Create a list of file descriptors to select requests from and a mapping of
        # file descriptor to the RPC server that is to handle the request
        admin_socket = self._admin_rpc_server.fileno()
        scep_socket = self._scep_rpc_server.fileno()
        spki_socket = self._spki_rpc_server.fileno()
        
        sockets = [admin_socket, scep_socket, spki_socket]
        socket_map = {admin_socket: self._admin_rpc_server,
                      scep_socket: self._scep_rpc_server,
                      spki_socket: self._spki_rpc_server}

        # Check for scheduled tasks initially
        schedule_count = 0
        
        # The request loop for server requests.
        # Note: The server does not daemonize itself; that is the responsibility of caller and is
        #       handled by the init-script.
        while not self.halt:
            try:
                (readable, writeable, errored) = \
                           select.select(sockets, [], sockets, 1)
            except select.error, err:
                # If select is interrupted by a signal, it is not an error so
                # silently ignore it.
                if err[0] != EINTR:
                    raise
                else:
                    return
            except KeyboardInterrupt:
                # If select is interrupted by a Control-C, set the halt flag
                # to exit.
                self.halt = True
                continue

            if readable or writeable:
                # Find the server responsible for each readable socket and
                # pass control onto its request handler.
                for fd in readable:
                    server = socket_map[fd]
                    server.handle_request()

                # There is a socket error. For hubris, just log it because it
                # must be a bug.
                for fd in errored:
                    Logging.debug(('daemon', 'run'),
                              'error fd: %d' % fd)

            if schedule_count <= 0:
                # Check schedule every 30 selects, or approximately 60 seconds
                schedule_count = 30
                for ca in self.get_certificate_managers().values():
                    ca.check_schedule()
            else:
                schedule_count -= 1

        Logging.info(('daemon', 'run'),
                     'Shutting down')

        # Shutdown each server
        for server in socket_map.values():
            server.server_close()
            
    def stop(self):
        for mc in self._certificate_managers:
            mc.stop_rmrsync()

        Logging.testing(('daemon', 'stop'),
                        'Halting')

        self.halt = True
        
class RPCServerRequestHandler(SimpleXMLRPCRequestHandler):
    def log_request(self, code=None, size=None):
        # Our requests are logged from the _dispatch method
        pass

# A base class for RPC servers
class RPCServer(SimpleXMLRPCServer):
    def __init__(self, server_daemon, address, quiet=False):
        Logging.info((self.IDENTITY, 'init'),
                     'Starting %s RPC Server' % self.IDENTITY)
        SimpleXMLRPCServer.__init__(self, address,
                                    requestHandler=RPCServerRequestHandler)

        self._server_daemon = server_daemon
        self.shutdown = False

        # Allow the server to reuse open sockets to prevent errors when quickly
        # restarting the server
        self.allow_reuse_address = True

        # Register all public methods defined by subclass
        for method in self.public_methods():
            self.register_function(method)

    def public_methods(self):
        # The base class has no public methods but subclasses must ensure that they include
        # any that might be added
        return []

    def stop(self):
        self.shutdown = True
        self.socket.shutdown(2)
        self.server_close()

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)

    def serve_forever(self):
         while not self.shutdown:
             self.handle_request()

    def _log_request(self, method, params):
        # Log the RPC method called and parameters in a pretty format
        print_stream = StringIO()
        pretty_printer = PrettyPrinter(depth=3, width=78, stream=print_stream, indent=1)
        pretty_printer.pprint(params)
        message = print_stream.getvalue().strip()
        
    def _authenticate(self, method, params):
        # By default, all access is granted and parameters are not modified
        return params
    
    def _dispatch(self, method, params):
        # Override the method dispatcher to include more logging

        # Ensure the method is both defined and listed as a public, callable method.
        # If not, return an exception to the caller.
        try:
            func = getattr(self, method)
            if func not in self.public_methods():
                raise Exception("method '%s' not supported" % method)
        except AttributeError:
            raise Exception("method '%s' not supported" % method)
        
        else:
            try:
                self._log_request(method, params)
                # Check the access, if necessary.
                params = self._authenticate(method, params)
                if params is False:
                    Logging.error((self.IDENTITY, 'request'),
                                  'Unable to dispatch request: Access denied')
                    result = {'error':'authenticationError',
                              'errorString':'Unable to perform request: Access denied'}
                else :
                    result = func(*params)
                
                self._log_request('result', result)
                return result

            except pg.InternalError:
                return {'error':'internalError',
                        'errorString':'There is a problem with the connection to the database ' + \
                        'in method %s' % str(method)}

                
            except:
                traceback.print_exc()
                Logging.error((self.IDENTITY, 'request'),
                              'Exception during dispatch', exc_info=True)
                return {'error':'internalError',
                        'errorString':'An unexpected internal error has '
                        'occurred; please check system log for details'}

# An implementation of an RPC server for handling user-interface requests.
class AdminRPCServer(RPCServer):
    # For security and simplicity, only listen on the localhost interface for requests by default.
    LISTEN_ADDRESS = 'localhost'
    LISTEN_PORT = 49801

    # Label for logging
    IDENTITY = 'Admin'

    # Exepected certificate request begin and end lines.
    VALID_CSR_HEADERS = ["-----BEGIN CERTIFICATE REQUEST-----",
                         "-----BEGIN NEW CERTIFICATE REQUEST-----"]
    VALID_CSR_FOOTERS = (("-----END CERTIFICATE REQUEST-----\n",
                          "-----END CERTIFICATE REQUEST-----\r\n",
                          "-----END CERTIFICATE REQUEST-----"),
                         ("-----END NEW CERTIFICATE REQUEST-----\n",
                          "-----END NEW CERTIFICATE REQUEST-----\r\n",
                          "-----END NEW CERTIFICATE REQUEST-----"))
    
    # Maximum aceeptable certificate request length.
    MAX_REQUEST_LENGTH = 8192

    def __init__(self, server_daemon, listen_address=None, listen_port=None, quiet=False):

        self._saved_revoked_dict = {}
        self._saved_granted_dict = {}
        
        if not listen_address:
            listen_address = AdminRPCServer.LISTEN_ADDRESS
        
        if not listen_port:
            listen_port = AdminRPCServer.LISTEN_PORT

        address = (listen_address, listen_port)
            
        RPCServer.__init__(self, server_daemon, address, quiet)
            

        self._init_regexps()

    def _init_regexps(self):
        # pre-compile regular expressions as an optimization
        self._regexp = re.compile("[\w\s\-]*")
        self._name_regexp = re.compile("[\w\s\.\-]*")
        self._name_ou_regexp = re.compile("[\w\s\.\-\/]*")
        self._keyidregex = re.compile("[0-9a-f]+.[0-9a-f\-]*")
    
    def public_methods(self):
        # Add Admin methods to the base public methods
        return RPCServer.public_methods(self) + \
               [self.get_ca_list,
                self.get_ca_info,
                self.key_sizes,
                self.expiry,
                self.get_ca_certificate,
                self.get_certificate_chain,
                self.find_cert,
                self.find_cert_by_serial,
                self.list_revoked,
                self.regenerate_revocation_list,
                self.list_granted,
                self.get_filename,
                self.create_ca,
                self.create_ca_csr,
                self.create_private_key_and_cert,
                self.cleanup_private_key_and_cert,
                self.get_key_filenames,
		self.get_key_filenames_with_pk12_pass,
                self.get_key_and_certificate,
                self.get_ca_dn,
                self.get_request_text,
                self.submit_cert_request,
                self.grant_cert_request,
                self.reject_cert_request,
                self.get_certfilename_by_serial,
                self.get_certificate_by_subject_name, 
                self.run_registration,
		self.get_ip_assignments,
                self.revoke_certificate,
                self.revoke_all_certs,
                self.revoke_ca_certificate,
                self.list_crl,
                self.scep_pending,
                self.scep_grant,
                self.scep_reject,
                self.spki_pending,
                self.spki_grant,
                self.spki_reject,
                self.csr_pending,
                self.revocation_pending,
                self.revocation_search,
                self.revocation_grant,
                self.revocation_reject,
		self.get_file_contents,
                self.expiry_pending,
                self.get_privileges,
                self.list_users,
                self.get_access_list,
                self.modify_access,
                self.modify_access_server]

    def _authenticate(self, method, parameters):
        Logging.debug((self.IDENTITY, '_authenticate'),
                      'parameters %s' % str(parameters))
        if len(parameters) > 0:
            # The authentication token is always this first parameter and is a three element list of
            # ['auth', username, sessionid]
            # 'auth' is included to tag the token and to disambiguate from other parameters;
            # sessionid is not used during authentication, but is included for potential debugging
            # purposes or to allow checking the validity of the session in the PHP session store.
            token = parameters[0]
            if type(token) is types.ListType and len(token) == 3 and token[0] == 'auth':
                username = token[1]
                # session_id is not used in authentication.
                session_id = token[2]

                # Remove authentication token from parameters
                #add the username to the list for logging purposes
                parameters = parameters[1:] + (username,)

            else:
                Logging.debug((self.IDENTITY, '_authenticate'),
                              'Invalid authentication token: %s' % str(token))
                # Remove authentication token from parameters
                if type(token) is types.ListType and len(token) == 0:
                    parameters = parameters[1:]
                username = None
        else:
            Logging.debug((self.IDENTITY, '_authenticate'),
                          'Authentication token missing from parameters')
            username = None

        Logging.debug((self.IDENTITY, '_authenticate'),
                          'Authenticating %s for %s' % (username, method))

        # Check the requested method against the list of authentication-required methods. 
        auth_required = AccessControlManager.getAuthRequired()
        if method in auth_required:
            Logging.info((self.IDENTITY, '_authenticate'),
                         'Authentication required for %s' % method)

            # Authentication is denied if there is not a valid authentication token.
            if username is None:
                Logging.error((self.IDENTITY, '_authenticate'),
                              'Missing username for authenticated method')
                return False

            # Validate authentication against the appropriate AccessControlManager
            access_manager_name = self._get_access_control_manager_name(method, parameters)
            Logging.debug((self.IDENTITY, '_authenticate'),
                          'Authenticating against access manager: %s' % str(access_manager_name))
            access_manager = self._server_daemon._access_control_managers[access_manager_name]

            if access_manager.checkAccess(username, method):
                Logging.info((self.IDENTITY, '_authenticate'),
                              'Authentication success for %s by %s' % (username, method))
                return parameters
            else:
                Logging.error((self.IDENTITY, '_authenticate'),
                              'Authentication failure for %s by %s' % (username, method))
                return False
        
# Logging.debug((self.IDENTITY, '_authenticate'),
#                       'About to return parameters')

        return parameters

    def _get_access_control_manager_name(self, method, parameters):
        # Get the name of the access control manager from the parameter list.
        # If the method is a server-authenticated method, use the 'server' access manager;
        # otherwise, use the authority name from the parameter list, which is the first parameter
        # of all methods I have audited. Additional manipulation could be used here if this is
        # not the case.
        
        if method in AccessControlManager._server_methods:
            manager_name = 'server'
        else:
            manager_name = parameters[0]

        if manager_name not in self._server_daemon._access_control_managers:
            # Uh oh, the discovered manager name is not loaded. Fail fast.
            Logging.error((self.IDENTITY, '_get_access_control_manager_name'),
                          'Access control manager not loaded: %s' % str(manager_name))
            return None

        return manager_name
    
    def _get_certificate_manager(self, ca_name):
        certificate_managers = self._server_daemon.get_certificate_managers()
        if ca_name in certificate_managers:
            return (True, certificate_managers[ca_name])
        else:
	    print 'do we get here 3'
            return (False, {'error':'invalidCAIdentifier',
                            'errorString':"CA '%s' does not exist" % ca_name})
        
    def get_ca_info(self, ca_name, username=""):
        # Return detailed information for a CA
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        
        return ca_result.get_ca_info()

    def get_ca_certificate(self, ca_name, format, username=""):
        # Return the certificate for ca_name in the DER- or PEM-encoding.
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result

        cacert = None
        try:
            cacert = ca_result.get_ca_certificate()
        except CertificateManagerError, e:
            Logging.error((self.IDENTITY, 'get_ca_cert'),
                          'Unable to load CA certificate', exc_info=True)
            return {'error': 'loadCertFailure',
                    'errorString': e.message}
        except:
            Logging.error((self.IDENTITY, 'get_ca_cert'),
                          'Unable to load CA certificate', exc_info=True)
            return {'error': 'loadCertFailure',
                    'errorString': 'internal error: %s' % e.args}

        if format == 'der':
            der_encoding = cacert.as_der()
            base64_encoding = base64.encodestring(der_encoding)
            return {'return':True, 'result': base64_encoding}
        elif format == 'pem':
            pem_encoding = cacert.as_pem()
            return {'return': True, 'result': pem_encoding}
        else:
            return {'error':'loadCertFailure',
                    'errorString': 'internal error: unknown encoding'}

    def get_certificate_chain(self, ca_name, username=""):
        # Return the CA certificate chain for ca_name in PEM-encoded form.
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result

        try:
            cert_chain = ca_result.get_certificate_chain()
            cert_chain_text = [str(cert.get_subject()) for cert in cert_chain]
            Logging.debug((self.IDENTITY, 'get_certificate_chain'),
                          'certificate chain: %s' % str(cert_chain_text))
        except CertificateManagerError:
            Logging.error((self.IDENTITY, 'get_certificate_chain'),
                          'Unable to load CA certificate', exc_info=True)

        pkcs7_signed = PKCS7()
        pkcs7_signed.set_type(PKCS7_SIGNED)
        pkcs7_signed.set_content_type(PKCS7_DATA)

        for certificate in cert_chain:
            pkcs7_signed.add_certificate(certificate)

        bio = BIO.MemoryBuffer()
        pkcs7_signed.write_der(bio)
        result = bio.read()

        encoded_result = base64.encodestring(result)

        return {'cert_chain': encoded_result}

    def find_cert(self, ca_name, search_cn, search_type="revoked", username=""):
        try:

            #find all the certs that have the substring search_cn in their CN
            if search_type == "revoked":
                
                result = {'size':0,
                          'terminalid':[],
                          'serial':[],
                          'revocationdate':[],
                          'username':[]}

                saved_revoked_list = self._saved_revoked_dict[ca_name]

                for i in range(len(saved_revoked_list['terminalid'])):
                    if saved_revoked_list['terminalid'][i].rfind(search_cn) is not -1:
                        result['terminalid'].append(saved_revoked_list['terminalid'][i])
                        result['serial'].append(saved_revoked_list['serial'][i])
                        result['revocationdate'].append(saved_revoked_list['revocationdate'][i])
                        result['username'].append(saved_revoked_list['username'][i])
                        result['size'] = result['size']+1

                if result['size'] > 0:
                    return result
                else:
                    return {'warning':'No Cert Found',
                            'warningString':'No cert with CN=%s found' % search_cn}
                
            elif search_type == "granted" or search_type == "grantedrevoke":
                result = []

                saved_granted_list = self._saved_granted_dict[ca_name]
                
                for (serial, subject, before, after, user) in saved_granted_list:
                    if subject.rfind(search_cn) is not -1:
                        result.append((serial, subject, before, after, user))
                if len(result) > 0:
                    return (len(result), result)
                else:
                    return {'warning':'No Cert Found',
                            'warningString':'No cert with CN=%s found' % search_cn}
            
        except ValueError:
            return {'warning':'No Cert Found',
                    'warningString':'No cert with %s in the CN found' % search_cn}


    def find_cert_by_serial(self, ca_name, serial, search_type="granted", username=""):

        #this is just here to make sure that _saved_granted_dict is created
        self.list_granted(ca_name)


        if search_type == "granted":
            result = []
            for ser in serial:
                for (searchserial, subject, before, after, user) in self._saved_granted_dict[ca_name]:
                    if searchserial == int(ser):
                        result.append((searchserial, subject, before, after, user))

            if len(result) > 0:
                return (len(result), result)
            else:
                return {'warning':'No Cert Found',
                        'warningString':'No cert with Serial(s) %s found' % str(serial)}

        #TODO:Add a search feature here for revoked certs

    def save_revoked_list(self, ca_name):
         # Return a table of revoked certificates.
            # TODO: terminalid?!?
            result = {'terminalid':[],
                      'serial':[],
                      'revocationdate':[],
                      'username':[]}

            (found, ca_result) = self._get_certificate_manager(ca_name)

            if not found:
                return ca_result
                
            revoked_list = ca_result.get_revoked_list()
            cert_index = ca_result.get_certificate_index()

            if len(revoked_list)==0:
                return {'warning':'No Revoked Certificates',
                        'warningString':'No certificates have been revoked.'}
        

            revoked_list.sort(lambda a, b: cmp(a['serialnumber'], b['serialnumber']))


            for i in revoked_list:
                serial = i['serialnumber']
                record = cert_index[str(serial)]
                terminalid = record[0]
                result['terminalid'].append(terminalid)
                result['serial'].append(serial)
                result['revocationdate'].append(i['revocationdate'])
                result['username'].append(i['username'])

            self._saved_revoked_dict[ca_name] = result

            return None

    def list_revoked(self, ca_name, start_index="0", username=""):

        if start_index == "0":

            save_list = self.save_revoked_list(ca_name)

            if save_list is not None:
                return save_list

            result = self._saved_revoked_dict[ca_name]

            return {'size':len(result['serial']),
                    'terminalid':result['terminalid'][0:100],
                    'serial':result['serial'][0:100],
                    'revocationdate':result['revocationdate'][0:100],
                    'username':result['username'][0:100]}
        else:

            if ca_name not in self._saved_revoked_dict.keys():
                save_list = self.save_revoked_list(ca_name)
                if save_list is not None:
                    return save_list
            
            index_int = int(start_index)
            saved_revoked_list = self._saved_revoked_dict[ca_name]
            
            return {'size':len(saved_revoked_list['serial']),
                    'terminalid':saved_revoked_list['terminalid'][index_int:index_int+100],
                    'serial':saved_revoked_list['serial'][index_int:index_int+100],
                    'revocationdate':saved_revoked_list['revocationdate'][index_int:index_int+100],
                    'username':saved_revoked_list['username'][index_int:index_int+100]}
        
    def regenerate_revocation_list(self, ca_name, username=""):
        # Regenerate the CRL for a CA.
        (found, ca_result) = self._get_certificate_manager(ca_name)

        if not found:
            return ca_result

        revoked_list = ca_result.get_revoked_list()
        result = ca_result.generate_revocation_list(revoked_list)

        return True

    def save_granted_dict(self, ca_name):

        # Return a list of granted certificate as a tuple: (serial, subject, before, after)
          result = []

          (found, ca_result) = self._get_certificate_manager(ca_name)

          if not found:
              Logging.debug((self.IDENTITY, 'save_granted_dict'),
                              'CA not found')
              return ca_result

          cert_list = ca_result.get_certificate_list()
          revoked_list = ca_result.get_revoked_list()
          revoked_serials = [i['serialnumber'] for i in revoked_list]
         
          if len(cert_list) == 1:
              # If the only certificate is the CA certificate then there is nothing to display.
              certificate = cert_list[0]
              ca_cert = ca_result.get_ca_certificate()
              if str(certificate[1]) == str(ca_cert.get_subject()) and \
                     certificate[0] == ca_cert.get_serial_number():
                  return {'warning':'No Granted Certificates',
                          'warningString':'No certificates have been granted.'}
          elif len(cert_list) - len(revoked_serials) == 1:
              # If the only non-revoked certificate is the CA certificate, then there is nothing to display.
              certificate = cert_list[0]
              ca_cert = ca_result.get_ca_certificate()
              if str(certificate[1]) == str(ca_cert.get_subject()) and \
                     certificate[0] == ca_cert.get_serial_number():
                  return {'warning':'No Granted Certificates',
                          'warningString':'All certificates have been revoked.'}
        
          for (serial, subject, before, after, user) in cert_list:
              if serial not in revoked_serials and serial != 1:
                  result.append((serial, subject, before, after, user))

          Logging.debug((self.IDENTITY, 'save_granted_list'),
                        'Saving granted dict')


          self._saved_granted_dict[ca_name] = result

          return None

    def list_granted(self, ca_name, start_index="0", username=""):

        #the saved list needs to be regenerated when we start looking at the
        #list or when we have added something and want to go directly to the
        #end of the new list
        
        
        if start_index == "":
            start_index = "0"

        if start_index == "0" or start_index == "last":

            save_list = self.save_granted_dict(ca_name)

            if save_list is not None:
                return save_list

            result = self._saved_granted_dict[ca_name]

            if start_index=="last":
                index_int = int(math.floor((len(result)-1)/100)*100)
                return (len(result), result[index_int:index_int+100])
            else:
                return (len(result), result[0:100])
        else:

            if ca_name not in self._saved_granted_dict.keys():
                save_list = self.save_granted_dict(ca_name)
                if save_list is not None:
                    return save_list
            
            saved_granted_list = self._saved_granted_dict[ca_name]
            index_int = int(start_index)
            return (len(saved_granted_list), saved_granted_list[index_int:index_int+100])

    def get_ca_list(self, username=""):
        # Return a list of CA titles which are loaded.
        result = []
        certificate_managers = self._server_daemon.get_certificate_managers()

        if len(certificate_managers) == 0:
            result = [False]

        for i in certificate_managers:
            result.append(certificate_managers[i].get_title())

        result.sort()
        return result

    def get_filename(self, ca_name, type, username=""):
        # Return a path to the CA certificate or CRL in DER- or PEM-encoded form
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        
        try:
            if type == "pem":
                filename = self._server_daemon._config\
                           .get_ca_certificate_pem_filename(ca_name)
            elif type == "der":
                filename = self._server_daemon._config\
                           .get_ca_certificate_der_filename(ca_name)
            elif type == "crlpem":
                filename = self._server_daemon._config\
                           .get_crl_filename(ca_name, 'pem')
                if not os.path.isfile(filename):
                    result = {'warning':'No CRL Available',
                              'warningString':'No certificates have been revoked, '
                              'so the CRL has not been generated yet.'}
                    return result
            elif type == "crlder":
                filename = self._server_daemon._config\
                           .get_crl_filename(ca_name, 'der')
            else:
                result = {'error':'invalidFileRequested', 
                          'errorString':'an invalid file was requested'}
                return result
            
            absolute_filename = os.path.abspath(filename)
            result = {'filename':absolute_filename,
                      'name':ca_name}
        except ConfigurationError, e:
            result = {'error': 'invalidConfiguration',
                 'errorString': e.message}
        return result

    def get_certfilename_by_serial(self, ca_name, serial, username=""):
        # Return the filename to a certificate with the given serial.
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:
            pem_filename = ca_result.get_certificate_filename(serial, 'pem')
            der_filename = ca_result.get_certificate_filename(serial, 'der')
            certificate = ca_result.get_certificate(serial)
            name = str(certificate.get_subject().CN)
            return {'return':True, 'certpem':pem_filename, 'certder':der_filename, 'name':name}
        except (StorageManagerError, CertificateManagerError), e:
            return {'error':'internalError',
                    'errorString':e.message}
        except:
            raise

    def get_certificate_by_subject_name(self, ca_name, subject, username=""):
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:
            return ca_result.get_certificate_by_subject_name(subject)
        except:
            raise


    def run_registration(self, ca_name, terminal_id, isp='testisp', 
                         ispip='127.0.0.1', username=""):
        Logging.debug((self.IDENTITY, 'run_registration'),
                       'running registration')
        cert = self.get_certificate_by_subject_name(ca_name, terminal_id, username)
        (found, ca_result) = self._get_certificate_manager(ca_name)
        tr = terminal_registration(self._server_daemon._config, cert, ca_name,
                                  ca_result, 
                                  self._server_daemon._access_control_managers[ca_name])
        Logging.debug((self.IDENTITY, 'run_registration'),
                        'about to call register terminal')
        tr.register_terminal(terminal_id, isp, ispip, cert)
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        
        #run the register hooks, this is most likely just an rmr_sync
        ca_result.run_register_hooks()

        return True

    def get_ip_assignments(self, ca_name, terminal_id, username):

        tr = terminal_registration(self._server_daemon._config, False, ca_name,
                                  False, False)

	#ip_assignments = tr.load_ip_assignments()
        ip_assignments = tr.get_ip_info(terminal_id)

	#in order for the string to be in the correct format to turn it back into a dict
	#everything must be strings, this helps to do that
	#ip_assignments[terminal_id]['vpn-block'] = '%s' % ip_assignments[terminal_id]['vpn-block']
	#ip_assignments[terminal_id]['vpn-address'] = '%s' % ip_assignments[terminal_id]['vpn-address']

        #syslog.syslog("Get IP Assignments: return string: %s" % str(ip_assignments[terminal_id]))

        return unicode(ip_assignments)
	#return str(ip_assignments[terminal_id])
        #return tr.load_ip_assignments()
       
         

    def create_ca(self, ca_name, subject_dict, options, username=""):
        # Create a CA private key and certificate.
        if ca_name == '' or not self._verify_input_with_regex(ca_name,
                                                              self._regexp):
            return {'error':'invalidCAName',
                    'errorString':'Invalid CA title: "%s"' % ca_name}

        for (key, value) in subject_dict.iteritems():
            
            if (key == 'O') and value != ''  \
                    and not self._verify_input_with_regex(value, self._name_regexp):
                return {'error':'invalidDN',
                        'errorString':'Invalid distingushed name: "%s=%s"'
                        % (key, value)}

            if (key == 'OU') and value != ''  \
                    and not self._verify_input_with_regex(value, self._name_ou_regexp):
                return {'error':'invalidDN',
                        'errorString':'Invalid distingushed name: "%s=%s"'
                        % (key, value)}
                    

            if (key != 'OU' and key != 'O' and (value == '' or \
                   not self._verify_input_with_regex(value, self._name_regexp))):
                return {'error':'invalidDN',
                        'errorString':'Invalid distingushed name: "%s=%s"'
                        % (key, value)}

             
        config = self._server_daemon._config
        overrides = {'title':ca_name}

        # If the private key is stored on a smartcard, override the configuration parameters
        # for private keys.
        if options.get('smartcard', False):
            private_key = options['private-key']
            overrides['private_key_file'] = private_key + \
                                            ''':%(dir)s/cflex.pub'''
            overrides['engine'] = 'musclecard'
            

        if options.get('key-sizes', False):
            overrides['key_sizes'] = options['key-sizes']

        #print options.get('pk_decrypt', False)

        if options.get('pk_decrypt', False):
            print 'SERVER DEAMON - Using pk_decrypt'
            overrides['pk_decrypt'] = 'True'
        else: 
            print 'SERVER DEAMON - NOT Using pk_dycrypt'


        if options.get('pk_decrypt_athena', False):
           overrides['pk_decrypt_athena'] = 'True'
           overrides['athena_pin'] = options.get('athena_pin')
            
        if options.get('pk_decrypt_luna', False):
           overrides['pk_decrypt_luna'] = 'True'
           overrides['luna_pin'] = options.get('luna_pin')
	   overrides['luna_enctype'] = options.get('luna_enctype')
	   overrides['luna_keynum'] = options.get('luna_keynum')
        # If the authority is to use LDAP for certificate storage, override the configuration
        # parameters to include the LDAP configuration.
        use_ldap = options.get('ldap', False)
        if use_ldap:
            ldap_options = options['ldap-options']
            overrides['ldap'] = 'true'
            overrides['ldap_uri'] = ldap_options['LDAPURI']
            overrides['ldap_login'] = ldap_options['LDAPlogin']
            overrides['ldap_password'] = ldap_options['LDAPpassword']
            overrides['ldap_basedn'] = ldap_options['LDAPbasedn']
            overrides['ldap_certificate_dn'] = ldap_options['LDAPdn']
            overrides['ldap_end_entity_class'] = ldap_options['LDAPendentity']
            overrides['ldap_aux_end_entity_classes'] = ldap_options['LDAPauxendentity']
            overrides['ldap_authority_class'] = ldap_options['LDAPauthority']
            overrides['ldap_aux_authority_classes'] = ldap_options['LDAPauxauthority']
            
        subject_tuple = CertificateManager.get_ordered_x509_tuple_from_dict(subject_dict)

        crl_dist = self._check_crl_dist_point(options.get('crl_dist', ''))
        overrides['crl_dist'] = crl_dist

        # Copy the configuration defaults to a new section for the new CA with overrides.
        try:
            config.duplicate_section('ca defaults', ca_name, overrides)
        except ConfigurationError, e:
            result = {'error':'invalidConfiguration',
                      'errorString': str(e)}
            return result
        
        # Initialize the new CA.
        # This should also initialize the CertificateManager storage backend and catch any
        # potential configuration errors.
        
        try:
            signature = options.get('signature', None)
            certificate_manager = CertificateManager(config, ca_name, signature)
        except CBNCAError, e:
            # An error occurred so do not save the configuration and remove the invalid section from the
            # configuration file.
            config.remove_section(ca_name)
            
            result = {'error':'internalError',
                      'errorString':e.message}
            return result
                
        # Add the new CA to the config and save the configuration file with the new
        # section.
        config.add_ca(ca_name)
        config.save()
        
        try:
            public_key = options.get('public-key', False)
            key_type = options.get('key-type', 'rsa')
            key_size = options.get('key-size', None)
            expiry_days = options.get('ex_days', 365)
            #crl_dist = self._check_crl_dist_point(options.get('crl_dist', ''))

            extensions = options.get('extensions', None)
            if extensions:
                extension_list = []
                for (extension, (value, critical)) in extensions.iteritems():
                    extension_list.append((extension, value, critical))
                extensions = extension_list
            Logging.debug(('ServerDaemon', 'create_ca'),
                          'Extensions: %s' % str(extensions))

            backend = config.get_backend()
	    
	    #This no longer needs to be done since the monster database is being used
	    #and the data base will be created before install
            #if backend == 'postgres':
            #    certificate_manager.init_db(username)
                
            certificate_manager.create_ca_certificate(subject_tuple, public_key,
                                                      signature_algorithm=signature,
                                                      key_type=key_type, key_size=key_size,
                                                      extensions=extensions, 
                                                      expiry_days=expiry_days,
                                                      crl_dist=crl_dist)
                                                     
            Logging.initialize_debug(config, ca_name)
            certificate_managers = self._server_daemon.get_certificate_managers()
            certificate_managers[ca_name] = certificate_manager
            certificate_managers[ca_name].schedule_regeneration()

            permissions = options.get('access', {})
            self._server_daemon._add_access_control(ca_name, permissions)
            result = {'return':True}
        except CBNCAError, e:
            config.remove_section(ca_name)
            config.remove_ca(ca_name)
            config.save()
            result = {'error':'internalError',
                      'errorString':e.message}
        except Exception, e:
            config.remove_section(ca_name)
            config.remove_ca(ca_name)
            config.save()
            raise

        return result

    def _check_crl_dist_point(self, point):
        if point[0:4] == 'URI:':
            return point
        else:
            return 'URI:' + point

    def create_ca_csr(self, ca_name, subject_dict, use_smartcard, private_key,
                      public_key, username=""):
        # Create a CA certificate request; similar to create_ca().
        if ca_name == '' or not self._verify_input_with_regex(ca_name,
                                                              self._regexp):
            return {'error':'invalidCAName',
                    'errorString':'Invalid CA title: "%s"' % ca_name}

        for key, value in subject_dict.iteritems():

            if (key == 'O') and value != ''  \
                    and not self._verify_input_with_regex(value, self._name_regexp):
                return {'error':'invalidDN',
                        'errorString':'Invalid distingushed name: "%s=%s"'
                        % (key, value)}

            if (key == 'OU') and value != ''  \
                    and not self._verify_input_with_regex(value, self._name_ou_regexp):
                return {'error':'invalidDN',
                        'errorString':'Invalid distingushed name: "%s=%s"'
                        % (key, value)}
                    

            if (key != 'OU' and key != 'O' and (value == '' or \
                   not self._verify_input_with_regex(value, self._name_regexp))):
                return {'error':'invalidDN',
                        'errorString':'Invalid distingushed name: "%s=%s"'
                        % (key, value)}
        
        config = self._server_daemon._config
        overrides = {'title':ca_name}

        if use_smartcard:
            overrides['private_key_file'] = private_key + \
                                            ''':%(dir)s/cflex.pub'''
            overrides['engine'] = 'musclecard'
        
        subject_tuple = CertificateManager\
                        .get_ordered_x509_tuple_from_dict(subject_dict)
        
        try:
            config.duplicate_section('ca defaults', ca_name, overrides)
        except ConfigurationError, e:
            result = {'error':'invalidConfiguration',
                      'errorString': str(e)}
        else:
            config.add_ca(ca_name)
            config.save()
            certificate_manager = CertificateManager(config,
                                                     ca_name)
            certificate_manager.create_ca_request(subject_tuple,
                                                  public_key)
            self._certificate_managers[ca_name] = certificate_manager
            result = {'return':True}
            
        return result
    
    def revoke_certificate(self, ca_name, serial, username=""):
        # Revoke a certificate
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:   
            return ca_result

        if type(serial) == types.ListType:
            serials = map(lambda x: int(x), serial)
        else:
            serials = [serial]

        failed_serials = []
        errors = []
        results_text = []
        
        for serial in serials:
            # We do not allow the CA certificate to be revoked from the web-interface;
            # it should be a administration script.
            if serial == ca_result.get_ca_certificate().get_serial_number() and \
                   str(ca_result.get_subject()) == str(ca_result.get_issuer()) :
                return {'error':'Invalid serial number provided',
                        'errorString':'Cannot revoked self-signed CA certificate'}

            result_text = StringIO()
            try:
                if not ca_result.revoke_certificate(serial, hooks_result_text=result_text, 
                                                    access_manager=self._server_daemon._access_control_managers[ca_name],
                                                    username=username):
                    failed_serials += [serial]
                    errors += ['Unable to save CRL']
                else:
                    result_text_value = self._string_buffer_value(result_text)

                    Logging.debug((self.IDENTITY, 'revoke_certificate'),
                                  'result_text: %s' % result_text_value)

                    if result_text_value:
                        results_text += [result_text_value]
                        
            except CertificateManagerError, e:
                failed_serials += [serial]
                errors += [str(e.message)]

        if errors:
            return {'error':'Unable to process all requested revocations',
                    'errorString':'Unable to process all requested revocations\n' +
                    string.join([('Serial: %d; Error: %s\n' % (int(serial), message))
                                 for (serial, message) in zip(failed_serials, errors)],
                                "\n")}
                        
        if results_text:
            return {'return':True, 'hooks_text':string.join(results_text, '\n')}
        else:
            return {'return':True}


    def revoke_all_certs(self, ca_name, username=""):
        (numOfCerts, granted_certs) = self.list_granted(ca_name)
        serials = []
        for cert in granted_certs:
            serials.append(cert[0])
        self.revoke_certificate(ca_name, serials, username)

        return {'return':True}

    def revoke_ca_certificate(self, ca_name, username=""):
        # Revoke a certificate
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:   
            return ca_result

        serial = ca_result.get_ca_certificate().get_serial_number()
            
        if type(serial) == types.ListType:
            serials = map(lambda x: int(x), serial)
        else:
            serials = [serial]
            
        failed_serials = []
        errors = []
        results_text = []

        result_text = StringIO()
        try:
            if not ca_result.revoke_certificate(serial, hooks_result_text=result_text, 
                                                username=username):
                failed_serials += [serial]
                errors += ['Unable to save CRL']
            else:
                result_text_value = self._string_buffer_value(result_text)
                
                Logging.debug((self.IDENTITY, 'revoke_ca_certificate'),
                              'result_text: %s' % result_text_value)
                
                if result_text_value:
                    results_text += [result_text_value]
                    
        except CertificateManagerError, e:
            failed_serials += [serial]
            errors += [str(e.message)]

        if errors:
            return {'error':'Unable to process all requested revocations',
                    'errorString':'Unable to process all requested revocations\n' +
                    string.join([('Serial: %d; Error: %s\n' % (int(serial), message))
                                 for (serial, message) in zip(failed_serials, errors)],
                                "\n")}
                        
        if results_text:
            return {'return':True, 'hooks_text':string.join(results_text, '\n')}
        else:
            return {'return':True}

    def clean_cert_request(self, request_pem):
        # Fix formatting of a submitted certificate signing request to ensure that line
        # endings are correct: a single '\n' character

        Logging.debug((self.IDENTITY, 'clean_cert_request'),
                      'In Clean CERT REQUEST')

        result = StringIO()
        request_buffer = StringIO(request_pem)
        for line in request_buffer:
            new_line = line.strip()
            if not new_line:
                continue
            result.write(new_line)
            result.write('\n')
        return result.getvalue()
            
    def submit_cert_request(self, ca_name, request_pem, username=""):
        Logging.debug((self.IDENTITY, 'submit_cert_request'),
                      'Start of submit cert req')

	#print "submit_cert_request"

        # Submit a certificate signing request in PEM format.
        # On success, it returns an ID for the request to complete the process
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result

        Logging.debug((self.IDENTITY, 'submit_cert_request'),
                              'About to enter CLEAN_cert_request')
        
        request_pem = self.clean_cert_request(request_pem)
        Logging.debug((self.IDENTITY, 'submit_cert_request'),
                      request_pem)
        
        if (len(request_pem) > self.MAX_REQUEST_LENGTH):
            Logging.error((self.IDENTITY, 'submit_cert_request'),
                         'Request length %d larger than maximum %d' %
                                (len(request_pem), self.MAX_REQUEST_LENGTH))
            return {'error':'Invalid Request',
                    'errorString':'An invalid X509 request was provided'}

        # Check the header and footer of the request
        headers_valid = False
        for valid_header in self.VALID_CSR_HEADERS:
            # Check the beginning of the request to see if it matches a valid
            # header.
            if self._request_begins_with(request_pem, valid_header):
                Logging.debug((self.IDENTITY, 'submit_cert_request'),
                              'Checking header %s' % valid_header)
                # Remember the index of the valid header in our list
                offset = self.VALID_CSR_HEADERS.index(valid_header)
                # Check the end of the request to see if it matches a
                # corresponding valid footer.
                for valid_footer in self.VALID_CSR_FOOTERS[offset]:
                    Logging.debug((self.IDENTITY, 'submit_cert_request'),
                         'Checking footer %s' % valid_footer)

                    if self._request_ends_with(request_pem, valid_footer):
                        # If this matches, we probably have a good request.
                        headers_valid=True
                        break
                   
                break

        if headers_valid:
            try:
                request_id = ca_result.create_temporary_cert_request(request_pem)
                return {'return':True, 'request_id':request_id}
            except:
                return {'return':False}
        else:
	    #print "headers not valid"
            Logging.error((self.IDENTITY, 'submit_cert_request'),
                          'Invalid certificate request header/footer')
            return {'error':'Invalid Request',
                    'errorString':'An invalid X509 request was provided'}

    def get_request_text(self, ca_name, request_id, username=""):
        # Return the informational payload of a given certificate signing request
        Logging.debug((self.IDENTITY, 'get_request_text'),
                      'real beginning')
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:

            Logging.debug((self.IDENTITY, 'get_request_text'),
                          'beginning')
            result_text = StringIO()
            text = ca_result.get_request_text(request_id, hooks_result=result_text)

            result_text_value = self._string_buffer_value(result_text)

            #Logging.debug((self.IDENTITY, 'get_request_text'),
            #              'result_text: %s' % result_text_value)

            # Compaq iLo requests insert bogus values in the name; filter them out
            # so the text is human-readable.
            text = text.replace('\x00', '')
            
            if result_text_value:
                return {'return':True, 'request':text, 'hooks_text':result_text_value}
            else:
                return {'return':True, 'request':text}
        except CertificateManagerError, e:
            return {'error':'CertificateManagerError',
                    'errorString':str(e)}
      
    def grant_cert_request(self, ca_name, request_id, options=None, username=""):
        # Grant a certificate signing request.
	
	if options.get('create_krb_prince', False):
	    self.setup_ker_conf(options.get('realm', ''),
	                        options.get('prince_name', ''))
	
            san = 'otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name'	
	else:
	    san = ""

	policy_file = options.get('policy_file', None)
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:
            result_text = StringIO()
            serial = ca_result.grant_request(request_id, hooks_result_text=result_text, 
                                             san=san,
					     policy_file = policy_file,
					     username=username)

            result_text_value = self._string_buffer_value(result_text)
            #Logging.debug((self.IDENTITY, 'grant_cert_request'),
            #              'result_text: %s' % result_text_value)

            if result_text_value:
		if os.path.exists('/tmp/tempssl.conf'):
		    os.remove('/tmp/tempssl.conf')
                return {'return':True, 'serial':serial, 'hooks_text':result_text_value}
            else:
		if os.path.exists('/tmp/tempssl.conf'):
		    os.remove('/tmp/tempssl.conf')
                return {'return':True, 'serial':serial}
        except CertificateManagerError, e:
            Logging.error((self.IDENTITY, 'grant_cert_request'),
                      'Unable to grant certificate', exc_info=True)
	    if os.path.exists('/tmp/tempssl.conf'):
		    os.remove('/tmp/tempssl.conf')
            return {'error':'internalError',
                    'errorString':e.message}
        except:
            raise
        
    def reject_cert_request(self, ca_name, request_id, username=""):
        # Reject a certificate signing request.
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:
            result_text = StringIO()
            result = ca_result.reject_request(request_id, hooks_result_text=result_text)
            result_text_value = self._string_buffer_value(result_text)

            #Logging.debug((self.IDENTITY, 'reject_cert_request'),
            #              'result_text: %s' % result_text_value)

            if result_text_value:
                return {'return':True, 'hooks_text':result_text_value}
            else:
                return {'return':True}
        except:
            raise

    def scep_grant(self, ca_name, transaction_id, options, username=""):


	
	if options.get('create_krb_prince', False):
	    self.setup_ker_conf(options.get('realm', ''),
	                        options.get('prince_name', ''))
	
            san = 'otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name'	
	else:
	    san = ""

	policy_file = options.get('policy_file', None)
        # Grant a pending SCEP certificate request.
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:
            result_text = StringIO()


            try:
                serial = ca_result.grant_request(transaction_id, request_type='scep',
                                                 hooks_result_text=result_text, san=san, 
						 policy_file=policy_file, username=username)
            except CertificateManagerError, e:
                #This is a bit of a hack but it should really never happen unless someone is
                #doing something screwy to allow the granging of a certificate to a terminal
                #that is not assigned
                return self.scep_reject(ca_name, transaction_id, username)

            result_text_value = self._string_buffer_value(result_text)

            #Logging.debug((self.IDENTITY, 'scep_grant'),
            #              'result_text: %s' % str(result_text_value))

            if result_text_value:
                return {'return':True, 'hooks_text':result_text_value}
            else:
                return {'return':True}
        except:
            raise

    def scep_reject(self, ca_name, transaction_id, username=""):
        # Reject a pending SCEP certificate request.
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:
            result_text = StringIO()
            result = ca_result.reject_request(transaction_id, request_type='scep',
                                              hooks_result_text=result_text)
            result_text_value = self._string_buffer_value(result_text)

            #Logging.debug((self.IDENTITY, 'scep_reject'),
            #              'result_text: %s' % result_text_value)

            if result_text_value:
                return {'return':True, 'hooks_text':result_text_value}
            else:
                return {'return':True}
        except:
            raise

    def scep_pending(self, ca_name, username=""):
        # Return a list of pending SCEP requests.
        result_attrs = ['subject', 'ip', 'transactionId:transid', 'hooks_result']
        
        (found, ca_result) = self._get_certificate_manager(ca_name)

        if not found:
            return ca_result

        pending = ca_result.get_scep_pending_list()
        pending_list = self._process_pending_list(pending, result_attrs)

        if pending_list:
            return pending_list
        else:
            return {'warning':'No Pending Requests',
                    'warningString':'Currently, there are no pending SCEP '
                    'requests.'}

    def spki_pending(self, ca_name, username=""):
        # Return a list of pending SCEP requests.
        result_attrs = ['subject', 'ip', 'user_name', 'user_email', 'reqtype', 'date', 'renew',
                        'request_id']
        
        (found, ca_result) = self._get_certificate_manager(ca_name)

        if not found:
            return ca_result

        pending = ca_result.get_spki_pending_list()
        pending_list = self._process_pending_list(pending, result_attrs)

        if pending_list:
            return pending_list
        else:
            return {'warning':'No Pending Requests',
                    'warningString':'Currently, there are no pending SPKI '
                    'requests.'}

    def csr_pending(self, ca_name, username=""):
        # Return a list of pending CSR requests.
        
        Logging.debug((self.IDENTITY, 'csr_pending'),
                      'csr_pending has been called')
        
        result_attrs = ['request_id', 'ip', 'subject', 'date']
        
        (found, ca_result) = self._get_certificate_manager(ca_name)

        if not found:
            return ca_result

        pending = ca_result.get_csr_pending_list()
        pending_list = self._process_pending_list(pending, result_attrs)

        if pending_list:
            return pending_list
        else:
            return {'warning':'No Pending Requests',
                    'warningString':'Currently, there are no pending CSR '
                    'requests.'}

    def revocation_pending(self, ca_name, username=""):
        result_attrs = ['user_name', 'user_email', 'phone_number', 'subject',
                        'description', 'ip', 'date', 'request_id']

        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result

        pending = ca_result.get_revocation_pending_list()
        pending_list = self._process_pending_list(pending, result_attrs)

        if not pending:
            return {'warning':'No Pending Requests',
                    'warningString':'Currently, there are no pending revocation '
                    'requests.'}
        
        return pending_list

    def revocation_search(self, ca_name, subject, username=""):
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result

        revocation_matches = ca_result.revocation_search(subject)

        if revocation_matches:
            return {'return':True, 'result':revocation_matches}
        else:
            return {'warning':'No Matching Certificates',
                    'warningString':'Currently, there are no certificates that '
                    'match the revocation request'}

    def expiry_pending(self, ca_name, username=""):
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result

        config = self._server_daemon._config

        # Get a list of certificates that will expire in the next 7 days
        to_expire = ca_result.get_expiry_pending_list(config.get_expiry_warning_days())

        # Get a list of certificates that have expired in the last 7 days
        have_expired = ca_result.get_expiry_recent_list(config.get_expiry_recent_days())

        result_attrs = ['serial', 'subject', 'issued_date', 'expiry_date']
        to_expire_pending_list = self._process_pending_list(to_expire,
                                                            result_attrs)
        have_expired_pending_list = self._process_pending_list(have_expired,
                                                               result_attrs)


        if not to_expire_pending_list:
            to_expire_pending_list = {'warning':'No Pending Expirations',
                                      'warningString':
                                      'Currently, there are no pending '
                                      'certificate expirations'}
        

        if not have_expired_pending_list:
            have_expired_pending_list = {'warning':'No Recent Expirations',
                                      'warningString':
                                      'Currently, there are no recently '
                                      'expired certificates'}

        return [to_expire_pending_list, have_expired_pending_list]
        
    def spki_grant(self, ca_name, request_id, username=""):
        # Grant a pending SPKI certificate request.
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:
            result_text = StringIO()

            serial = ca_result.grant_request(request_id, request_type='spki',
                                             hooks_result_text=result_text, username=username)

            result_text_value = self._string_buffer_value(result_text)

            #Logging.debug((self.IDENTITY, 'spki_grant'),
            #              'result_text: %s' % str(result_text_value))

            if result_text_value:
                return {'return':True, 'hooks_text':result_text_value}
            else:
                return {'return':True}
        except:
            raise

    def spki_reject(self, ca_name, transaction_id, username=""):
        # Reject a pending SPKI certificate request.
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:
            result_text = StringIO()
            result = ca_result.reject_request(transaction_id, request_type='spki',
                                              hooks_result_text=result_text)
            result_text_value = self._string_buffer_value(result_text)

            #Logging.debug((self.IDENTITY, 'spki_reject'),
            #              'result_text: %s' % result_text_value)

            if result_text_value:
                return {'return':True, 'hooks_text':result_text_value}
            else:
                return {'return':True}
        except:
            raise

    def revocation_grant(self, ca_name, request_id, username=""):
        # Grant a pending revocation request.
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:
            result_text = StringIO()

            serial = ca_result.grant_request(request_id, request_type='revocation',
                                             hooks_result_text=result_text, username=username)

            result_text_value = self._string_buffer_value(result_text)

            #Logging.debug((self.IDENTITY, 'revocation_grant'),
            #              'result_text: %s' % str(result_text_value))

            if result_text_value:
                return {'return':True, 'hooks_text':result_text_value}
            else:
                return {'return':True}
        except:
            raise

    def revocation_reject(self, ca_name, transaction_id, username=""):
        # Reject a pending revocation request.
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        try:
            result_text = StringIO()
            result = ca_result.reject_request(transaction_id, request_type='revocation',
                                              hooks_result_text=result_text)
            result_text_value = self._string_buffer_value(result_text)

            #Logging.debug((self.IDENTITY, 'revocation_reject'),
            #              'result_text: %s' % result_text_value)

            if result_text_value:
                return {'return':True, 'hooks_text':result_text_value}
            else:
                return {'return':True}
        except:
            raise

    def get_file_contents(self, filename, username=""):


        fileNameParts = filename.split(".")
        fileExtension = fileNameParts[len(fileNameParts) - 1]

        if (fileExtension == 'pem'): 
            f = open(filename, 'r')
            contents = f.read()
            f.close()	
	

            return {'filename': filename, 'contents': contents}
        else:
        
            with open(filename, "rb") as binary_file:
                encoded_string = base64.b64encode(binary_file.read())    
            return {'filename': filename, 'contents': encoded_string}
            #return{'filename': 'thisshouldnothappen', 'contents':'bad contents'}

    def _process_pending_list(self, pending, result_attrs):
        results = {'hooks_text':[]}
        for attr in result_attrs:
            split_attr = attr.split(':')
            if len(split_attr) == 2:
                (r_attr, p_attr) = split_attr
            else:
                r_attr = p_attr = attr
                
            results[r_attr] = []

        if not pending:
            return False

        for p in pending:
            for attr in result_attrs:
                split_attr = attr.split(':')
                if len(split_attr) == 2:
                    (r_attr, p_attr) = split_attr
                else:
                    r_attr = p_attr = attr

                results[r_attr].append(p[p_attr])
            
            if 'hooks_text' in p:
                result_text = p['hooks_text']
                result_text_value = self._string_buffer_value(result_text)
                
                if result_text_value:
                    results['hooks_text'].append(result_text_value)

        return results

    def _process_Subject_Alt_Name(self, altname, subject_cn):
        if altname is None or altname == '':
            Logging.debug((self.IDENTITY, 'process subject alt name'),
                          'no subjectAltName')
            return None

       # If CN is a hostname, it should also appear as a subjectAltName
       # if we have any subjectAltNames.
        extra = ''
        if self._ip_rx.match(subject_cn):
            extra = 'IP:' + subject_cn
        elif self._dns_rx.match(subject_cn):
            extra = 'DNS:' + subject_cn
        if extra != '' and extra not in altname.split(','):
            altname += ',' + extra

        Logging.debug((self.IDENTITY, 'process subject alt name'),
                      'return subjectAltName: %s' % altname)
        return altname

    #This will initialize the openssl conf needed to initialize the kdc prince
    def setup_ker_conf(self, realm, prince):
    	krb_template = open("/opt/cbnca/etc/krb_template", "r")
    	template_contents = krb_template.read()
    	krb_template.close()
    	tempconf = open("/tmp/tempssl.conf", "w+")

    	print >> tempconf, template_contents % (realm, prince)

    	tempconf.close()

	self.create_ker_prince(prince, realm)

    def create_ker_prince(self, prince, realm):

	password = uuid.uuid4()


	print ['kadmin', '-p', 'kadmin/admin', '-k', '-t', '/tmp/testkt2',
                        '-r', realm,
                        '-q', '"add_principal +requires_preauth -pw %s %s"' % (str(password), prince)]
        result = subprocess.call(['kadmin', '-p', 'kadmin/admin', '-k', '-t', '/tmp/testkt2', 
                        '-r', realm, 
                        '-q', 'add_principal +requires_preauth -pw %s %s' % (str(password), prince)])
	print 'KADMIN Response: %s' % str(result)


    _ip_re = '''^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'''
    _ip_rx = re.compile(_ip_re)

    _dns_re = '''^[a-zA-Z0-9_.-]*$'''
    _dns_rx = re.compile(_dns_re)

    def create_private_key_and_cert(self, ca_name, subject_cn, subject_ou,
                                    subject_on, subject_c, options, policy_file=None, username=""):
        # Create a private key and certificate for the given subject.
        # On success, return a key identifier for completing the process.
        (found, ca_result) = self._get_certificate_manager(ca_name)

        if not found:
            return ca_result
         
        if not self._verify_input_with_regex(subject_cn, self._name_regexp):
            return {'error':'invalidCN',
                    'errorString':'The CN must contain only alphanumeric '
                    'characters'} 
        try:
            ca_certificate = ca_result.get_ca_certificate()
            ca_subject_name = ca_certificate.get_subject()
            subject_name = ca_result.get_tuple_from_x509_name(ca_subject_name)
            Logging.debug((self.IDENTITY, 'create_private_key_and_cert'),
                           'subject_name: %s' % str(subject_name))
            #subject_name = subject_name[:-1]
            subject_name = ()

            ous = subject_ou.split('/')

            subject_name += ('O', subject_on),
            for ou in ous:
                subject_name += ('OU', ou),
            subject_name += ('CN', subject_cn),
            subject_name += ('C', subject_c), 
           
            subject_name_tuple = tuple(subject_name)
            result_text = StringIO()
            key_type = options.get('key_type', 'rsa')
            key_size = options.get('key_size', None)
            if key_size:
                key_size = int(key_size)
            signature_algorithm = options.get('signature', None)
            ex_days = options.get('ex_days', None)
            ex_mins = options.get('ex_mins', None)
            st_days = options.get('st_days', None)
            st_mins = options.get('st_mins', None)

            # Just pass "IP:1.2.3.4,DNS:1.2.3.4" and OpenSSL will do the rest.
            subjectAltName = self._process_Subject_Alt_Name(
                options.get('subject_alt_name', None), subject_cn)

	    if options.get('create_krb_prince', False):
		self.setup_ker_conf(options.get('realm', ''),
				    options.get('prince_name', ''))
		if subjectAltName is not None:
            		subjectAltName  = '%s,%s' % (subjectAltName, 
						     'otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name')
		else:
			subjectAltName = 'otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name'
	
            (keyid, serial) = ca_result.create_temporary_private_key_and_cert(
                subject_name_tuple, key_type=key_type, key_size=key_size,
                signature_algorithm=signature_algorithm,
                ex_days=ex_days, ex_mins=ex_mins,
                st_days=st_days, st_mins=st_mins,
                hooks_result=result_text,
                subjectAltName=subjectAltName,
		policy_file=policy_file,
                username=username)
        except IOError, e:
            Logging.error((self.IDENTITY, 'create_private_key_and_cert'),
                          'Unable to initialize private key and certificat', exc_info=True)
            return {'error':'internalError',
                    'errorString':'An unexpected internal error has '
                    'occurred; please check system log for details'}
        except CertificateManagerError, e:
            Logging.error((self.IDENTITY, 'create_private_key_and_cert'),
                          'Unable to initialize private key and certificat', exc_info=True)
            return {'error':'internalError',
                    'errorString':e.message}
        except ConfigurationError, e:
            Logging.error((self.IDENTITY, 'create_private_key_and_cert'),
                          'Unable to initialize private key and certificat', exc_info=True)
            return {'error':'invalidConfiguration',
                    'errorString': str(e)}
        result_text_value = self._string_buffer_value(result_text)
        
        Logging.debug((self.IDENTITY, 'create_temporary_private_key_and_cert'),
                      'result_text: %s' % result_text_value)
        if result_text_value:
            return {'return':True, 'keyid':keyid, 'serial': serial, 'hooks_text':result_text_value}
        else:
            return {'return':True, 'keyid':keyid, 'serial': serial}

    def get_key_filenames(self, ca_name, keyid, username=""):
        # Return private key and certificate filenames for the given key ID.
        (found, ca_result) = self._get_certificate_manager(ca_name)

        if not found:
            return ca_result

        if not self._verify_input_with_regex(keyid, self._keyidregex):
            return {'error':'InvalidKey',
                    'errorString':'An invalid key identifier was given'}

        filenames = ca_result.encode_temporary_key_and_cert(keyid)

        result = {}
        for key, filename in filenames.iteritems():
            result[key] = os.path.abspath(filename)

        pem_certificate_filename = result['certpem']
        certificate = X509.load_cert(pem_certificate_filename)
        result['name'] = str(certificate.get_subject().CN)
        
        return result

    def get_key_filenames_with_pk12_pass(self, ca_name, keyid, pk12pass, username=""):
        # Return private key and certificate filenames for the given key ID.
        (found, ca_result) = self._get_certificate_manager(ca_name)

        if not found:
            return ca_result

        if not self._verify_input_with_regex(keyid, self._keyidregex):
            return {'error':'InvalidKey',
                    'errorString':'An invalid key identifier was given'}

        filenames = ca_result.encode_temporary_key_and_cert(keyid, pk12pass)

        result = {}
        for key, filename in filenames.iteritems():
            result[key] = os.path.abspath(filename)

        pem_certificate_filename = result['certpem']
        certificate = X509.load_cert(pem_certificate_filename)
        result['name'] = str(certificate.get_subject().CN)
        
        return result

    def get_key_and_certificate(self, ca_name, key_id, username=""):
        (found, ca_result) = self._get_certificate_manager(ca_name)

        if not found:
            return ca_result

        if not self._verify_input_with_regex(key_id, self._keyidregex):
            return {'error':'InvalidKey',
                    'errorString':'An invalid key identifier was given'}

        filenames = ca_result.encode_temporary_key_and_cert(key_id)
        pem_certificate = filenames['certpem']
        pem_key = filenames['keypem']

        pem_certificate_file = file(pem_certificate, 'r')
        pem_key_file = file(pem_key, 'r')

        file_buffer = StringIO()
        file_buffer.write(pem_certificate_file.read())
        file_buffer.write('\n')
        file_buffer.write(pem_key_file.read())

        ca_result.cleanup_temporary_key_and_cert(key_id)
        
        return {'return':True, 'result':self._string_buffer_value(file_buffer)}

    def get_ca_dn(self, ca_name, username=""):
        (found, ca_result) = self._get_certificate_manager(ca_name)

        if not found:
            return ca_result
         

        try:
            ca_certificate = ca_result.get_ca_certificate()
            ca_subject_name = ca_certificate.get_subject()
            subject_name = ca_result.get_tuple_from_x509_name(ca_subject_name)
            
            result = {}
            for t in subject_name:
                result[t[0]] = t[1]

            Logging.debug((self.IDENTITY, 'get_ca_dn'),
                          'DN: %s' % str(result))
        except IOError, e:
            Logging.error((self.IDENTITY, 'get_ca_dn'),
                          'Unable to get CA DN', exc_info=True)
            return {'error':'internalError',
                    'errorString':'An unexpected internal error has '
                    'occurred; please check system log for details'}
        
        return result

    def cleanup_private_key_and_cert(self, ca_name, key_id, username=""):
        # Remove left over keys and certs from create_private_key_and_cert
        (found, ca_result) = self._get_certificate_manager(ca_name)

        if not found:
            return ca_result

        ca_result.cleanup_temporary_key_and_cert(key_id)
        return {'return':True}

    def list_crl(self, ca_name, username=""):
        # Return informational text for the CRL
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            return ca_result
        
        try:
            crlText = ca_result.get_crl_text()
            return {'crlText':crlText}
        except CertificateManagerError, e:
            return {'warning':'No CRL Available',
                    'warningString':'No certificates have been revoked, so the '
                    'CRL has not been generated yet.'}

    def get_privileges(self, ca_name, username=""):
        Logging.debug((self.IDENTITY, 'get_privileges'),
                      'ca_name: %s' % str(ca_name))

        if ca_name == 'access_control':
            ca_name = ''
        if ca_name == '':
            ca_name = 'server'
        else:
            (found, ca_result) = self._get_certificate_manager(ca_name)
            
            if not found:
                return ca_result

        access_manager = self._server_daemon._access_control_managers[ca_name]
        result = access_manager.getPrivileges(username)
        return {'return':True, 'privileges':result}

    def list_users(self, ca_name, username=""):
        if ca_name == '' or ca_name == 'server':
            ca_name = 'server'
        else:
            (found, ca_result) = self._get_certificate_manager(ca_name)
            
            if not found:
                return ca_result

        access_manager = self._server_daemon._access_control_managers[ca_name]
        result = access_manager.list_users()

        return result

    def get_access_list(self, ca_name, username=""):
        if ca_name == '' or ca_name == 'server':
            ca_name = 'server'
        else:
            (found, ca_result) = self._get_certificate_manager(ca_name)
            
            if not found:
                return ca_result

        access_manager = self._server_daemon._access_control_managers[ca_name]
        result = access_manager.get_access_list()

        return result

    def modify_access(self, ca_name, access_list, username=""):
        #print 'modify_access'
        #print ca_name
        #print access_list
        access_manager = self._server_daemon._access_control_managers[ca_name]
        result = access_manager.modify_access(access_list[:-1])
        return {'modify_access' : access_list}

    def modify_access_server(self, ca_name, access_list, username=""):
        #print 'modify_access_server'
        #print ca_name
        #print access_list
        access_manager = self._server_daemon._access_control_managers[ca_name]
        result = access_manager.modify_access(access_list[:-1])
        return {'modify_access' : access_list}

    def key_sizes(self, ca_name, username=""):
        
        (found, ca_result) = self._get_certificate_manager(ca_name)

        #if the ca isn't found then we are looking for the key sizes to initialize a ca
        if not found:
            key_sizes = self._server_daemon._config.get_key_sizes('ca defaults')
            #return ca_result
        else:
            key_sizes = ca_result.load_key_sizes()
            
        ecdsa_curves = key_sizes.get('ecdsa', [])
        ecdsa_sizes = []
        for curve in ecdsa_curves:
            curve_nid = getattr(EC, 'NID_%s' % curve, False)
            if curve_nid is not False:
                ecdsa = EC.gen_params(curve_nid)
                size = len(ecdsa)
                ecdsa_sizes.append(size)
        key_sizes['ecdsa'] = ecdsa_sizes
        
        return key_sizes
        
    def expiry(self, ca_name, username=""):
        
        (found, ca_result) = self._get_certificate_manager(ca_name)

        #if the ca isn't found then we are looking for the key sizes to initialize a ca
        if not found:
            expiry = self._server_daemon._config.get_ca_expiry('ca defaults')
        else:
            expiry = self._server_daemon._config.get_ca_expiry(ca_name)

        return expiry
        
    def _verify_input_with_regex(self, input, regex):
        match = regex.match(input)
        if match and match.group() == input:
            return True
        return False

    def _request_begins_with(self, request, valid_header):
       if request[:len(valid_header)]==valid_header:
           return True
       return False
   
    def _request_ends_with(self, request, valid_footer):
        if request[(len(valid_footer)*-1):]==valid_footer:
            return True
        return False

    def _string_buffer_value(self, result_text_buffer):
        result_text_buffer.seek(0)
        result_text_value = result_text_buffer.getvalue().strip()
        result_text_buffer.close()

        return result_text_value

# Implementation of RPC server for handling SCEP requests
class SCEPServer(RPCServer):
    # Default interface and port for RPC server
    LISTEN_ADDRESS = 'localhost'
    LISTEN_PORT = 49802

    # Identity for logging
    IDENTITY = 'SCEP'

    # Some SCEP constant definitions
    PKCSREQ = '19'
    CERTREP = '3'
    GETCERTINITIAL = '20'
    GETCERT = '21'
    GETCRL = '22'

    STATUS_SUCCESS = '0'
    STATUS_FAILURE = '2'
    STATUS_PENDING = '3'

    FAILINFO_BADALG = '0'
    FAILINFO_BADMESSAGECHECK = '1'
    FAILINFO_BADREQUEST = '2'
    FAILINFO_BADTIME = '3'
    FAILINFO_BADCERTID = '4'

    def __init__(self, server_daemon, listen_address=None, listen_port=None, quiet=False):
        if not listen_address:
            listen_address = SCEPServer.LISTEN_ADDRESS

        if not listen_port:
            listen_port = SCEPServer.LISTEN_PORT
            
        address = (listen_address, listen_port)
            
        RPCServer.__init__(self, server_daemon, address, quiet)
    
    def public_methods(self):
        # SCEP server has only one public method; merge it with the base methods.
        return RPCServer.public_methods(self) + [self.pkcs7]

    def pkcs7(self, ca_name, message, ip):

        # Process a SCEP request
        logging_context = (self.IDENTITY, 'pkcs7')

        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            Logging.warn(logging_context, 
                          'invalid request for CA: %s',  ca_name)
            return ca_result

        # Append the CA title to make the logging
        logging_context += (ca_name,)
        
        if ip is None:
            ip = "unknown ip"
        
        try:
            # Create a PKCS#7 object from the encoded form
            pkcs7 = self._create_pkcs7(message)
        except:
            Logging.error(logging_context,
                          'received invalid encoding for request from ip: %s' % ip,
                          exc_info=True)
            return self._create_failing_response(
                ca_result, None, None, SCEPServer.FAILINFO_BADREQUEST)
        else:
            Logging.info(logging_context,
                         'pkcs7: received request from ip: %s' % ip)

        try:
            self._verify_pkcs7_signature(pkcs7, ca_result.get_ca_certificate(),
                                         logging_context)
        except:
            Logging.error(logging_context, 'verify failed', exc_info=True)

            # TODO: is it safe to get the signed attributes when the signature
            # failed?
            d = pkcs7.signed_attributes()

            if 'transId' in d:
                transaction_id = ASN1.ASN1_String(d['transId'])
            else:
                transaction_id = None

            if 'senderNonce' in d:
                sender_nonce = ASN1.ASN1_String(d['senderNonce'])
            else:
                sender_nonce = None

            return self._create_failing_response(ca_result,
                                                 transaction_id,
                                                 sender_nonce,
                                                 SCEPServer.FAILINFO_BADMESSAGECHECK)

        try:
            signed_attr = pkcs7.signed_attributes()
        except:
            Logging.error(logging_context, 'invalid signed attributes',
                          exc_info=True)
            return self._create_failing_response(ca_result,
                                                 None, None,
                                                 SCEPServer.FAILINFO_BADMESSAGECHECK)
        else:
            Logging.debug(logging_context,
                'received attributes %s' % str(signed_attr.keys()))

        # Check for existence of required signed attributes
        for attr in ['messageType', 'senderNonce']:
            if not attr in signed_attr:
                Logging.debug(logging_context,
                             'Missing signed attribute: %s' % attr)
                return self._create_failing_response(ca_result,
                                              None, None,
                                              SCEPServer.FAILINFO_BADMESSAGECHECK)
        messageType = ASN1.ASN1_String(signed_attr['messageType'])
        #messageType = ASN1.ASN1_String(signed_attr['test0'])

        # Handle the request
        if str(messageType) == SCEPServer.PKCSREQ:
            return self._handle_pkcsreq(ca_result, pkcs7, ip)
        elif str(messageType) == SCEPServer.GETCERTINITIAL:
            return self._handle_getcertinitial(ca_result, pkcs7, ip)
        elif str(messageType) == SCEPServer.GETCERT:
            return self._handle_getcert(ca_result, pkcs7, ip)
        else:
            Logging.error(logging_context,
                          'Unknown message type: %s' % str(messageType))
            return self._create_failing_response(ca_result,
                                                 None, None,
                                                 SCEPServer.FAILINFO_BADREQUEST)

    def _verify_pkcs7_signature(self, pkcs7, ca_certificate, logging_context):
        # Check the signature on a PKCS7 object using the CA certificate
        cert_stack = X509.X509_Stack()
        signers = pkcs7.get0_signers(cert_stack)
        if len(signers) > 0:
            signer_cert = signers[0]
            subject = str(signer_cert.get_subject())
            issuer = str(signer_cert.get_issuer())
            
            # if the subject and the issuer are equal, then verify the
            # self-signed certificate
            if subject == issuer:
                Logging.debug(logging_context,
                              'verifying self-signature')
                self_signed_verify = pkcs7.verify_self_signed()
                if 0 == self_signed_verify:
                    Logging.debug(logging_context,
                                  'self-signature verified')
		    #return True
            else:
                # Check that the request is signed by the CA
                Logging.debug(logging_context,
                              'verifying signature')
                cert_stack = X509.X509_Stack()
                cert_store = X509.X509_Store()
                cert_store.add_x509(ca_certificate)
                verify = pkcs7.verify(cert_stack, cert_store)
                Logging.testing(logging_context, 'CA signature verified')
                return True
        else:
            Logging.warn(logging_context, 'No signatures on request')
            return False

    def _handle_envelope(self, ca, pkcs7, ip, load_request=False,
                         load_issuer_and_subject=False, load_issuer_and_serial=False):
        # Extract informational payload from pkcs7 object
        logging_context = (self.IDENTITY, 'envelope', ca.get_title())

        Logging.info(logging_context, 'handling envelope')

        result = {}
        
        data_bio = BIO.MemoryBuffer()

        # Get the signed attributes that are mandatory
        signed_attr = pkcs7.signed_attributes()
        transaction_id = ASN1.ASN1_String(signed_attr['transId'])
        sender_nonce = ASN1.ASN1_String(signed_attr['senderNonce'])
        hex_sender_nonce = self._nonce_string(signed_attr['senderNonce'])
        #transaction_id = ASN1.ASN1_String(signed_attr['test5'])
        #sender_nonce = ASN1.ASN1_String(signed_attr['test4'])
        #hex_sender_nonce = self._nonce_string(signed_attr['test4'])

        result['transaction_id'] = transaction_id
        result['sender_nonce'] = sender_nonce
        result['hex_sender_nonce'] = hex_sender_nonce

        # Load the enveloped data from the content portion of the pkcsCertReqSigned object
        try:
            pkcs7.data(data_bio)
            Logging.debug(logging_context,
                         'received %d bytes of data' % len(data_bio))
        except:
            Logging.error(logging_context,
                         'cannot extract data from pkcs7', exc_info=True)
            return (False, self._create_failing_response(ca, transaction_id,
                                                         sender_nonce,
                                                         SCEPServer.FAILINFO_BADMESSAGECHECK))

        try:
            envelope = load_pkcs7_bio_der(data_bio)
        except:
            Logging.error(logging_context,
                          'cannot load pkcs7 data', exc_info=True)
            return (False, self._create_failing_response(ca, transaction_id,
                                                         sender_nonce,
                                                         SCEPServer.FAILINFO_BADMESSAGECHECK))

        if not envelope.type() == PKCS7_ENVELOPED:
            Logging.error(logging_context,
                          'data not enveloped', exc_info=True)
            return (False, self._create_failing_response(ca, transaction_id,
                                                         sender_nonce,
                                                         SCEPServer.FAILINFO_BADMESSAGECHECK))
        Logging.debug(logging_context,
                       'data is %s' % envelope.type(text_name=True))


        # The envelope is encrypted to the CA. Decrypt it to obtain the informational payload.
        try:
            decrypted_bio = ca.decrypt_envelope(envelope)
        except:
            Logging.error(logging_context,
                          'unable to decrypt envelope', exc_info=True)
            return (False, self._create_failing_response(ca, transaction_id,
                                                         sender_nonce,
                                                         SCEPServer.FAILINFO_BADMESSAGECHECK))

        if load_request:
            # The pkcsCertReq informational payload contains a certificate signing request.
            try:
                decrypted_bio = ca.decrypt_envelope(envelope)
                request = X509.load_request_bio(decrypted_bio)
                result['request'] = request
            except:
                Logging.error(logging_context,
                              'unable to decrypt envelope', exc_info=True)
                return (False, self._create_failing_response(ca, transaction_id,
                                                             sender_nonce,
                                                             SCEPServer.FAILINFO_BADMESSAGECHECK))
        elif load_issuer_and_subject:
            # The pkcsGetCertInitial informational payload contains an issuerAndSubject object.
            issuer_and_subject = X509.load_issuer_and_subject_bio(decrypted_bio)
            result['issuer'] = str(issuer_and_subject.issuer())
            result['subject'] = str(issuer_and_subject.subject())

        elif load_issuer_and_serial:
            # The pkcsGetCert informational payload contains a issuerAndSerial object.
            issuer_and_serial = X509.load_issuer_and_serial_bio(decrypted_bio)
            result['issuer'] = str(issuer_and_serial.issuer())
            result['serial'] = int(issuer_and_serial.serial())
        
        return (True, result)

    def _handle_pkcsreq(self, ca, pkcs7, ip):
        # Handle a new SCEP request
        logging_context = (self.IDENTITY, 'pkcsreq', ca.get_title())

        Logging.info(logging_context, 'handling PKCSReq')
        
        (valid, result) = self._handle_envelope(ca, pkcs7, ip, load_request=True)
        if not valid:
            return result
        
        cert_stack = X509.X509_Stack()
        signers = pkcs7.get0_signers(cert_stack)

        # The request must be signed only by the certificate subject.
        if len(signers) is not 1:
            Logging.error(logging_context,
                          'missing self-signed certificate')
            return self._create_failing_response(ca, transaction_id,
                                                 sender_nonce,
                                                 SCEPServer.FAILINFO_BADMESSAGECHECK)
        else:
            signer_cert = signers[0]

        subject = result['request'].get_subject()
        
        Logging.debug(logging_context, 'subject %s' % subject)
        Logging.debug(logging_context, 'transId %s' % result['transaction_id'])
        Logging.debug(logging_context, 'nonce %s' % result['hex_sender_nonce'])

        # Save out data that needs to persist between requests:
        #   subject, transid, sendernonce, and self-signed cert
        Logging.debug(logging_context, "%s %s %s %s %s" % (result['request'].as_pem(),
                                       str(result['transaction_id']),
                                       str(subject),
                                       result['hex_sender_nonce'],
                                       str(ip)))
        ca.create_pending_scep_request(result['request'].as_pem(),
                                       str(result['transaction_id']),
                                       str(subject),
                                       result['hex_sender_nonce'],
                                       str(ip),
                                       signer_cert)

        return self._create_pending_response(ca, result['transaction_id'],
                                             result['sender_nonce'])
    
    def _handle_getcertinitial(self, ca, pkcs7, ip):
        # Handle a GetCertInitial request
        logging_context = (self.IDENTITY, 'getcertinitial', ca.get_title())
        
        Logging.info(logging_context, 'handling CertInitial')

        (valid, result) = self._handle_envelope(ca, pkcs7, ip, load_issuer_and_subject=True)
        if not valid:
            return result

        Logging.debug(logging_context, 'issuer %s' % result['issuer'])
        Logging.debug(logging_context, 'transId %s' % result['transaction_id'])
        Logging.debug(logging_context, 'nonce %s' % result['hex_sender_nonce'])

        transaction_id = result['transaction_id']
        sender_nonce = result['sender_nonce']

        if ca.check_rejected_scep_request(transaction_id):
            Logging.info(logging_context,
                         'transaction %s has been rejected' % transaction_id)
            result = self._create_failing_response(ca, transaction_id,
                                                   sender_nonce,
                                                   SCEPServer.FAILINFO_BADREQUEST)
        elif ca.check_pending_scep_request(transaction_id):
            Logging.info(logging_context,
                         'transaction %s is pending' % transaction_id)
            result = self._create_pending_response(ca, transaction_id,
                                                   sender_nonce)
        else:
            # Get the serial number of the newly issued certificate, and the
            # self-signed certificate that was included in the initial
            # enrollment request.
            result = ca.check_granted_scep_request(transaction_id)
            if result:
                (client_cert, self_signed_cert) = result
                Logging.info(logging_context,
                             'transaction %s is granted' % transaction_id)

                Logging.debug(logging_context, 'self-signed cert: %s' % self_signed_cert.as_pem())

                # Respond with a SUCCESS CertRep using the self-signed certificate
                # as the recipient
                result = self._create_success_response\
                         (ca, transaction_id, sender_nonce, client_cert,
                          recipient_cert=self_signed_cert)
            else:
                Logging.info(logging_context,
                             'transaction %s is not granted')
                # This shouldn't occur because we have previously checked that the transaction
                # has not been rejected and is not pending.
                result = self._create_failing_response(ca, transaction_id,
                                                       sender_nonce,
                                                       SCEPServer.FAILINFO_BADREQUEST)
  
        return result

    def _handle_getcert(self, ca, pkcs7, ip):
        # Handle a GetCert request.
        logging_context = (self.IDENTITY, 'getcert', ca.get_title())
        
        Logging.info(logging_context, 'handling GetCert')

        # The requester includes a issuer and serial for the certificate it wishes to retrieve.
        (valid, result) = self._handle_envelope(ca, pkcs7, ip, load_issuer_and_serial=True)
        if not valid:
            return result

        issuer = result['issuer']
        serial = result['serial']
        transaction_id = result['transaction_id']
        hex_sender_nonce = result['hex_sender_nonce']
        sender_nonce = result['sender_nonce']
        
        Logging.debug(logging_context, 'issuer %s' % issuer)
        Logging.debug(logging_context, 'serial %d' % serial)
        Logging.debug(logging_context, 'transId %s' % transaction_id)
        Logging.debug(logging_context, 'nonce %s' % hex_sender_nonce)

        cert_stack = X509.X509_Stack()
        signers = pkcs7.get0_signers(cert_stack)

        # The requester must sign the GetCert request and include it's CA-issued certificate.
        if len(signers) is not 1:
            Logging.error(logging_context,
                          'missing certificate')
            return self._create_failing_response(ca, transaction_id,
                                                 sender_nonce,
                                                 SCEPServer.FAILINFO_BADMESSAGECHECK)
        else:
            signer_cert = signers[0]

        # Find the certificate with the given serial number
        try:
            cert_response = ca.get_certificate(serial)
        except CertificateManagerError, e:
            return self._create_failing_response(ca, transaction_id,
                                                 sender_nonce,
                                                 SCEPServer.FAILINFO_BADMESSAGECHECK)
        # Check that the issuer of the found certificate matches the requested issuer.
        ca_cert = ca.get_ca_certificate()
        ca_subject = ca_cert.get_subject()
        if str(ca_subject) != str(issuer):
            Logging.error(logging_context,
                          'request issuer invalid')
            return self._create_failing_response(ca, transaction_id,
                                                 sender_nonce,
                                                 SCEPServer.FAILINFO_BADMESSAGECHECK)

        result = self._create_success_response(ca, transaction_id, sender_nonce,
                                               cert_response, recipient_cert=signer_cert)

        return result

    def _create_failing_response(self, ca, transaction_id, recipient_nonce,
                                 fail_info):

        # Create and return a Failure response with the given attributes.
        Logging.info((self.IDENTITY, 'response', ca.get_title()),
                     'creating FAILURE response')

        signed_attributes = []

        # Transaction ID can be empty if the message signature could not be
        # verified
        if transaction_id:
            transaction_id_attr = X509.create_string_attribute('transId',
                                                               transaction_id)
            signed_attributes.append(transaction_id_attr)

        # Recipient nonce can be empty if the message signature could not be
        # verified.
        if recipient_nonce:
            recipient_nonce_attr = X509.create_string_attribute(
                'recipientNonce',
                recipient_nonce,
                asn1_type=ASN1.ASN1_OCTETSTRING)
            signed_attributes.append(recipient_nonce_attr)

        # Create and include a new nonce for this message.
        sender_nonce_attr = self._create_sender_nonce()
        signed_attributes.append(sender_nonce_attr)

        cert_rep_attr = self._create_attribute('messageType',
                                               SCEPServer.STATUS_PENDING)
        signed_attributes.append(cert_rep_attr)
        
        pki_status_attr = self._create_attribute('pkiStatus',
                                                 SCEPServer.STATUS_FAILURE)
        signed_attributes.append(pki_status_attr)
        
        fail_info_attr = self._create_attribute('failInfo',
                                                fail_info)
        signed_attributes.append(fail_info_attr)
        
        return self._create_response(ca, signed_attributes)

        
    def _create_pending_response(self, ca, transaction_id, recipient_nonce):
        # Create and return a message indicating the status of a transaction is still pending confirmation.
        Logging.info((self.IDENTITY, 'response', ca.get_title()),
                      'creating PENDING response')


                     
        transaction_id_attr = X509.create_string_attribute('transId',
                                                           transaction_id)

        recipient_nonce_attr = X509.create_string_attribute('recipientNonce',
                                                            recipient_nonce,
                                                            asn1_type=ASN1.ASN1_OCTETSTRING)

        sender_nonce_attr = self._create_sender_nonce()

        cert_rep_attr = self._create_attribute('messageType',
                                               SCEPServer.CERTREP)

        pki_status_attr = self._create_attribute('pkiStatus',
                                                 SCEPServer.STATUS_PENDING)

        signed_attributes = [transaction_id_attr,
                             recipient_nonce_attr,
                             sender_nonce_attr,
                             cert_rep_attr,
                             pki_status_attr]
        
        return self._create_response(ca, signed_attributes)

    def _create_success_response(self, ca, transaction_id, recipient_nonce,
                                 client_cert, recipient_cert=None):
        # Create and return a message for a succesful enrollment, including the given client certificate.
        Logging.info((self.IDENTITY, 'response', ca.get_title()),
                      'creating success response')

                     
        # Create the list of authenticated attributes in the response
        transaction_id_attr = X509.create_string_attribute('transId',
                                                           transaction_id)

        recipient_nonce_attr = X509.create_string_attribute('recipientNonce',
                                                            recipient_nonce,
                                                            asn1_type=ASN1.ASN1_OCTETSTRING)

        sender_nonce_attr = self._create_sender_nonce()

        cert_rep_attr = self._create_attribute('messageType',
                                               SCEPServer.CERTREP)

        pki_status_attr = self._create_attribute('pkiStatus',
                                                 SCEPServer.STATUS_SUCCESS)

        signed_attributes = [transaction_id_attr,
                             recipient_nonce_attr,
                             sender_nonce_attr,
                             cert_rep_attr,
                             pki_status_attr]

        cacert = ca.get_ca_certificate()

        # Create the 'pkcsCertRep' degenerate PKCS#7 object containing the issued certificate chain.
        pkcsCertRep = PKCS7()
        pkcsCertRep.set_type(PKCS7_SIGNED)
        pkcsCertRep.set_content_type(PKCS7_DATA)
        pkcsCertRep.add_certificate(client_cert)
        pkcsCertRep.add_certificate(cacert)

        # Use the DER-encoded object as the data portion.
        bio = BIO.MemoryBuffer()
        pkcsCertRep.write_der(bio)
        bio.write_close()

        return self._create_response(ca, signed_attributes,
                                     recipient=recipient_cert, data=bio)

    def _create_response(self, ca, signed_attributes, recipient=None,
                         data=None):
        # Create and return a response and handle all the required enveloping.
        Logging.debug((self.IDENTITY, 'response', ca.get_title()),
                        'creating PKCS7 response')
        pkcs7_signed = PKCS7()
        pkcs7_signed.set_type(PKCS7_SIGNED)
        pkcs7_signed.set_content_type(PKCS7_DATA)

        # If there is a data payload, encrypt it to the given recipient certificate.
        if data:
            recipient_stack = X509.X509_Stack()

            Logging.debug((self.IDENTITY, 'response', ca.get_title()),
                            'encrypting response for %s %d' %
                            (str(recipient.get_subject()),
                             recipient.get_serial_number()))

            recipient_stack.push(recipient)
            p7e = PKCS7.encrypt(data, recipient_stack, flags=PKCS7_BINARY)
            encrypted_bio = BIO.MemoryBuffer()
            p7e.write_der(encrypted_bio)
        else:
            encrypted_bio = None
        
        attributes = X509.X509_Attribute_Stack()

        for attr in signed_attributes:
            attributes.push(attr)

        # Sign the message and attributes with the CA key.
        bio = pkcs7_signed.add_signature(attributes, ca.get_ca_certificate(),
                                         ca._get_ca_private_key(),
                                         data=encrypted_bio)

        # Include the recipient certificate chain.
        if recipient:
            pkcs7_signed.add_certificate(recipient)

        pkcs7_signed.add_certificate(ca.get_ca_certificate())
        bio = BIO.MemoryBuffer()
        pkcs7_signed.write_der(bio)
        result = bio.read()

        encoded_result = base64.encodestring(result)
        Logging.debug((self.IDENTITY, 'response', ca.get_title()),
                      'encoded resuls: %s' % encoded_result)

        return encoded_result

    def _get_certificate_manager(self, ca_name):
	exc_type, exc_value, exc_traceback = sys.exc_info()
	traceback.print_tb(exc_traceback, limit=10, file=sys.stdout)
        certificate_managers = self._server_daemon.get_certificate_managers()
        if ca_name in certificate_managers:
            return (True, certificate_managers[ca_name])
        else:
	    print 'do we get here 1'
            return (False, {'error':'invalidCAIdentifier',
                            'errorString':"CA '%s' does not exist" % ca_name})

    def _log_request(self, method, params):
        print_stream = StringIO()
        pretty_printer = PrettyPrinter(depth=3, width=78,
                                       stream=print_stream, indent=1)
        pretty_printer.pprint(params)
        message = print_stream.getvalue().strip()
        
        if method == 'result':
            Logging.debug((self.IDENTITY, 'request'),
                          '%s\n(%s)' % (method, message))
        else:
            Logging.debug((self.IDENTITY, 'request'),
                          '%s\n%s' % (method, message))

    def _create_pkcs7(self, data):
        bio = BIO.MemoryBuffer()
        bio.write('-----BEGIN PKCS7-----\n')
        bio.write(data.strip())
        bio.write('\n-----END PKCS7-----\n')
        pkcs7 = load_pkcs7_bio(bio)
        return pkcs7

    def _nonce_string(self, s):
        bio = BIO.MemoryBuffer()
        nonce = ASN1.ASN1_String(s)
        nonce.data(bio)
        nonce_buffer = bio.read()
        
        result = ''
        for i in nonce_buffer:
            result += ('%02X' % ord(i))
        return result

    def _create_sender_nonce(self):
        sender_nonce = Rand.rand_bytes(16)
        while '\x00' not in sender_nonce:
            sender_nonce = Rand.rand_bytes(16)
        asn1_sender_nonce = ASN1.ASN1_String()
        asn1_sender_nonce.set(sender_nonce)

        sender_nonce_attr = X509.create_string_attribute('senderNonce',
                                                         asn1_sender_nonce,
                                                         asn1_type=ASN1.ASN1_OCTETSTRING)
        return sender_nonce_attr

    def _create_attribute(self, key, value):
        asn1_string = ASN1.ASN1_String()
        asn1_string.set(value)
        cert_rep_attr = X509.create_string_attribute(key, asn1_string)
        return cert_rep_attr

class SPKIServer(RPCServer):
    # Default interface and port for RPC server
    LISTEN_ADDRESS = 'localhost'
    LISTEN_PORT = 49803

    # Identity for logging
    IDENTITY = 'SPKI'

    def __init__(self, server_daemon, listen_address=None, listen_port=None, quiet=False):
        if not listen_address:
            listen_address = SPKIServer.LISTEN_ADDRESS

        if not listen_port:
            listen_port = SPKIServer.LISTEN_PORT
        
        address = (listen_address, listen_port)
            
        RPCServer.__init__(self, server_daemon, address, quiet)
    
    def public_methods(self):
        return RPCServer.public_methods(self) + [self.submit_request,
                                                 self.request_info,
                                                 self.request_revocation]

    def _get_certificate_manager(self, ca_name):
	exc_type, exc_value, exc_traceback = sys.exc_info()
	traceback.print_tb(exc_traceback, limit=10, file=sys.stdout)
        certificate_managers = self._server_daemon.get_certificate_managers()
        if ca_name in certificate_managers:
            return (True, certificate_managers[ca_name])
        else:
	    print 'do we get here 2'
            return (False, {'error':'invalidCAIdentifier',
                            'errorString':"CA '%s' does not exist" % ca_name})

    def submit_request(self, ca_name, request, request_attributes):
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            Logging.warn((self.IDENTITY, 'SPKIServer', 'submit_request'), 
                         'invalid request for CA: %s',  ca_name)
            return ca_result

        try:
            request = request.replace('\n', '')
            ip = request_attributes['ip']
            subject = request_attributes['subject']
            user_name = request_attributes['user_name']
            user_email = request_attributes['user_email']
            request_type = request_attributes['reqtype']
            renew = request_attributes['renew']
        except KeyError, e:
            Logging.error((self.IDENTITY, 'SPKIServer', 'submit_request'),
                          "Request attributes missing key '%s'" % str(e))
            return {'return':False}
            
        result = ca_result.create_pending_spki_request(request, subject, ip, user_name,
                                                       user_email, request_type, renew)
        return {'return':True, 'result':result}

    def request_info(self, ca_name, request_id):
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            Logging.warn((self.IDENTITY, 'SPKIServer', 'request_info'), 
                         'invalid request for CA: %s',  ca_name)
            return ca_result

        try:
            result = ca_result.get_spki_request_info(request_id)
        except StorageManagerError, e:
            Logging.error((self.IDENTITY, 'SPKIServer', 'request_info'),
                          'Unable to load request %s: %s' % (request_id, e))
            return  {'error':'requestNotFound',
                     'errorString':"Certificate request '%s' does not exist" % request_id}


        return {'return': True, 'result':result}

    def request_revocation(self, ca_name, request_attributes):
        (found, ca_result) = self._get_certificate_manager(ca_name)
        if not found:
            Logging.warn((self.IDENTITY, 'SPKIServer', 'submit_request'), 
                         'invalid request for CA: %s',  ca_name)
            return ca_result

        try:
            user_name = request_attributes['user_name']
            user_email = request_attributes['user_email']
            phone_number = request_attributes['phone_number']
            subject = request_attributes['subject']
            description = request_attributes['description']
            ip = request_attributes['ip']
        except KeyError, e:
            Logging.error((self.IDENTITY, 'SPKIServer', 'request_revocation'),
                          "Request attributes missing key '%s'" % str(e))
            return {'return':False}

        result = ca_result.create_revocation_request(subject, user_name, user_email,
                                                     phone_number, ip, description)

        return {'return':True, 'result':result}

if __name__ == '__main__':
    config_filename = sys.argv[1]

    
	
    try:
        config = Config.load_file(config_filename)
        #if config.get_mlock(): 
        #    ret = pymlock.pymlock('test')
        #    if ret != 0:
        #        print 'Was unable to run mlock successfully'
        #        sys.exit(1)
        
    except ConfigurationError, e:
        print str(e)
        sys.exit(1)

    try:
        server = ServerDaemon(config)
    except ConfigurationError, e:
        print str(e)
        sys.exit(1)
    
    server.run()
