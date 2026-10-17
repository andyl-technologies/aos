"""Controlled source/real loopback TLS transport tests, never R2 qualification."""

import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


loss = load('controlled_cleanup_loss', '_hub-managed-cleanup-loss.py')
runtime = load('controlled_cleanup_runtime', '_hub-managed-cleanup-runtime.py')
controller = load('controlled_cleanup_controller', '_hub-managed-terminal-cleanup.py')


def offered():
    return {'original': {'upload_id':'a'*32,'ordinal':0}, 'protected_profile_digest':'b'*64,
            'issued_at':int(time.time()), 'expires_at':int(time.time())+30}


def arm_for(request):
    return {'version':1,'originalSha256':hashlib.sha256(loss.encode(request['original'])).hexdigest(),
            'protectedProfileDigest':'b'*64,'helperInput':{},'expiresAt':int(time.time())+60}


class SelectionTests(unittest.TestCase):
    def test_exact_original_profile_and_actual_deadline_are_required(self):
        request=offered()
        arm=arm_for(request)
        self.assertEqual(loss.validate_arm(arm,loss.encode(request),int(time.time())),request)
        for field,value in (('original',{'upload_id':'c'*32,'ordinal':0}),
                            ('protected_profile_digest','c'*64),('expires_at',arm['expiresAt']+1)):
            with self.assertRaises(ValueError):
                loss.validate_arm(arm,loss.encode({**request,field:value}),int(time.time()))
        with self.assertRaises(ValueError):
            loss.validate_arm(arm,loss.encode(request),arm['expiresAt'])

    def test_duplicate_fields_and_custody_change_refuse(self):
        with self.assertRaises(ValueError):
            json.loads('{"version":1,"version":1}',object_pairs_hook=loss.closed)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            file=root/'original'
            file.write_bytes(b'actual controlled file')
            file.chmod(0o600)
            self.assertEqual(loss.private_bytes(file,64),file.read_bytes())
            file.chmod(0o644)
            with self.assertRaises(ValueError):
                loss.private_bytes(file,64)
            (root/'alias').symlink_to(file)
            with self.assertRaises(OSError):
                loss.private_bytes(root/'alias',64)

    def test_generic_unknown_cannot_be_completed_response_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'cleanup-loss'
            root.mkdir(mode=0o700)
            exchange=root/'exchange-0001'
            exchange.mkdir(mode=0o700)
            loss.retain(root/'arm-consumed.json',loss.encode({'exchange':str(exchange),'originalSha256':'a'*64}))
            loss.retain(exchange/'exchange.json',loss.encode({'outcome':'unknown','errorKind':'OSError'}))
            with self.assertRaises(ValueError):
                runtime.lost_receipt({'nativeRoot':directory,'originalSha256':'a'*64})

    def test_cold_restart_refuses_missing_actual_process_before_signals(self):
        with patch.object(runtime,'runner_command',side_effect=ValueError('no actual namespace')):
            with patch.object(runtime.os,'pidfd_open',side_effect=AssertionError('unexpected signal preparation')):
                with self.assertRaises(ValueError):
                    runtime.cold_restart({'workerProcess':{'pid':1,'logFile':'/actual/worker.log'},
                        'workerRoot':'/actual'})

    def test_cold_restart_refuses_another_log_before_control_or_signals(self):
        with patch.object(runtime,'runner_command',side_effect=AssertionError('unexpected control')):
            with self.assertRaises(ValueError):
                runtime.cold_restart({'workerProcess':{'logFile':'/other/worker.log'},
                                      'workerRoot':'/selected'})

    def test_controller_refuses_wrong_prefix_before_guest_action(self):
        prepared={'coordinates':{'cleanupPrefix':'other','gcPrefix':'expected','runId':'a'*32}}
        with self.assertRaises(ValueError):
            controller.run_managed_terminal_cleanup_window(None,None,None,{},prepared,{}, {},
                None,None,None,None,None,None)


class TlsTransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.root=Path(self.temporary.name)
        openssl=os.environ['AOS_MANAGED_CLEANUP_TEST_OPENSSL']
        if not openssl.startswith('/nix/store/'):
            raise ValueError('test TLS tool must be source-built AOS OpenSSL')
        self.certificate=self.root/'certificate.pem'
        self.key=self.root/'key.pem'
        result=subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
            '-keyout',str(self.key),'-out',str(self.certificate)],
            stdin=subprocess.DEVNULL,capture_output=True,check=False,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.requests=[]
        self.request_headers=[]
        self.status=200
        parent=self

        class ControlledTlsReply(BaseHTTPRequestHandler):
            def log_message(self,*args):
                pass

            def do_POST(self):
                parent.requests.append(self.rfile.read(int(self.headers['Content-Length'])))
                parent.request_headers.append(dict(self.headers))
                body=b'controlled complete reply'
                self.send_response(parent.status)
                self.send_header('Content-Length',str(len(body)))
                self.send_header(loss.SIGNATURE,'c'*64)
                self.end_headers()
                self.wfile.write(body)

        self.upstream=HTTPServer(('127.0.0.1',0),ControlledTlsReply)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certificate,self.key)
        self.upstream.socket=context.wrap_socket(self.upstream.socket,server_side=True)
        self.thread=threading.Thread(target=self.upstream.serve_forever)
        self.thread.start()
        self.evidence=self.root/'evidence'
        self.evidence.mkdir(mode=0o700)
        self.configuration={'root':str(self.evidence),'caFile':str(self.certificate),
            'caSha256':hashlib.sha256(self.certificate.read_bytes()).hexdigest(),
            'workerAddress':'127.0.0.1','armFile':str(self.evidence/'arm.json')}
        self.server=loss.CleanupServer(self.configuration)
        self.server_thread=threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.thread.join()
        self.temporary.cleanup()

    def connection(self,config,context):
        raw=socket.create_connection(self.upstream.server_address,timeout=5)
        tls=context.wrap_socket(raw,server_hostname='localhost')
        peer=hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
        connection=http.client.HTTPConnection('localhost',self.upstream.server_port,timeout=5)
        connection.sock=tls
        return connection,peer

    def receipt(self):
        path=self.evidence/('exchange-%04d'%self.server.sequence)/'exchange.json'
        deadline=time.monotonic()+2
        while not path.exists():
            self.assertLess(time.monotonic(),deadline)
            time.sleep(0.01)
        return json.loads(path.read_bytes())

    def request(self,body):
        connection=http.client.HTTPConnection('127.0.0.1',4660,timeout=5)
        try:
            connection.request('POST',loss.ROUTE,body=body,headers={loss.SIGNATURE:'d'*64,'Host':'localhost:4643',
                'x-aos-fleet-request-id':'e'*32,'x-aos-storage-call-id':'f'*32})
            response=connection.getresponse()
            return response.status,response.read()
        finally:
            connection.close()

    def test_actual_tls_forward_retains_exact_metadata(self):
        body=loss.encode(offered())
        with patch.object(loss,'upstream_connection',self.connection):
            self.assertEqual(self.request(body),(200,b'controlled complete reply'))
        self.assertEqual(self.requests,[body])
        self.assertEqual(self.request_headers[0]['Host'],'localhost:4643')
        self.assertEqual(self.request_headers[0]['x-aos-fleet-request-id'],'e'*32)
        self.assertEqual(self.request_headers[0]['x-aos-storage-call-id'],'f'*32)
        receipt=self.receipt()
        self.assertEqual(receipt['outcome'],'ordinary_forwarded_response')
        self.assertEqual(receipt['request']['sha256'],hashlib.sha256(body).hexdigest())
        self.assertIsNotNone(receipt['tlsPeerCertificateSha256'])

    def test_completed_loss_requires_authenticator_before_any_downstream_reply(self):
        request=offered()
        loss.retain(self.evidence/'arm.json',loss.encode(arm_for(request)))
        called=[]

        def controlled_authenticator(*arguments):
            called.append(arguments[3:])
            return {'proof':{'sourceTestOnly':True}}

        with patch.object(loss,'upstream_connection',self.connection), patch.object(
                loss,'authenticate_completion',controlled_authenticator):
            with self.assertRaises((OSError,http.client.RemoteDisconnected)):
                self.request(loss.encode(request))
        self.assertEqual(len(called),1)
        self.assertEqual(called[0][2],b'controlled complete reply')
        self.assertTrue(self.server.consumed)
        self.assertEqual(self.receipt()['outcome'],
            'authenticated_completed_response_deliberately_lost')

    def test_upstream_refusal_and_failed_authentication_never_satisfy_loss(self):
        for status in (409,200):
            with self.subTest(status=status):
                self.status=status
                request=offered()
                if (self.evidence/'arm.json').exists():
                    (self.evidence/'arm.json').unlink()
                loss.retain(self.evidence/'arm.json',loss.encode(arm_for(request)))
                self.server.consumed=False
                with patch.object(loss,'upstream_connection',self.connection), patch.object(
                        loss,'authenticate_completion',side_effect=ValueError('controlled MAC refusal')):
                    with self.assertRaises((OSError,http.client.RemoteDisconnected)):
                        self.request(loss.encode(request))
                receipt=self.receipt()
                self.assertEqual(receipt['outcome'],'unknown')

    def test_wrong_tls_hostname_refuses_before_upstream_http(self):
        def wrong_hostname(configuration, context):
            raw=socket.create_connection(self.upstream.server_address,timeout=5)
            try:
                context.wrap_socket(raw,server_hostname='different-worker')
            finally:
                raw.close()
            raise AssertionError('foreign TLS identity unexpectedly accepted')

        with patch.object(loss,'upstream_connection',wrong_hostname):
            with self.assertRaises((OSError,http.client.RemoteDisconnected)):
                self.request(loss.encode(offered()))
        self.assertEqual(self.requests,[])
        self.assertEqual(self.receipt()['outcome'],'unknown')

    def test_actual_main_publishes_only_post_bind_pinned_readiness(self):
        # Release this test's controlled listener so the actual executable can
        # acquire the same fixed port. It performs no upstream request.
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()
        config={**self.configuration,'version':1,'workerAddress':'10.0.0.2',
            'nativeHelper':sys.executable,
            'nativeHelperSha256':hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()}
        config_path=self.root/'initial.json'
        loss.retain(config_path,loss.encode(config))
        process=subprocess.Popen([sys.executable,str(Path(loss.__file__)),
            '--configuration',str(config_path)],stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            ready=self.evidence/'ready.json'
            deadline=time.monotonic()+5
            while not ready.exists():
                self.assertIsNone(process.poll())
                self.assertLess(time.monotonic(),deadline)
                time.sleep(0.01)
            proc=Path('/proc')/str(process.pid)
            selected={'lossProcess':{'pid':process.pid,'ownerUid':proc.stat().st_uid,
                'startTicks':(proc/'stat').read_text().rpartition(') ')[2].split()[19],
                'environmentSha256':hashlib.sha256((proc/'environ').read_bytes()).hexdigest(),
                'commandLineSha256':hashlib.sha256((proc/'cmdline').read_bytes()).hexdigest(),
                'executableSha256':hashlib.sha256((proc/'exe').read_bytes()).hexdigest()},
                'readyFile':str(ready),'configurationSha256':hashlib.sha256(config_path.read_bytes()).hexdigest(),
                'listenerSourceSha256':hashlib.sha256(Path(loss.__file__).read_bytes()).hexdigest()}
            self.assertEqual(runtime.readiness(selected)['pid'],process.pid)
            with socket.create_connection(('127.0.0.1',4660),timeout=1):
                pass
            with self.assertRaises(ValueError):
                runtime.readiness({**selected,'configurationSha256':'0'*64})
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_wrong_sql_original_refuses_before_tls_dispatch(self):
        request=offered()
        loss.retain(self.evidence/'arm.json',loss.encode(arm_for(request)))
        with patch.object(loss,'upstream_connection',self.connection):
            with self.assertRaises((OSError,http.client.RemoteDisconnected)):
                self.request(loss.encode({**request,'original':{'upload_id':'e'*32,'ordinal':0}}))
        self.assertEqual(self.requests,[])
        self.assertFalse(self.server.consumed)


if __name__=='__main__':
    unittest.main()
