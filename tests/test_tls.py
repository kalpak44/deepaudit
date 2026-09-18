from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from deepaudit.demo import create_server
from deepaudit.policy import Scope, Target
from deepaudit.transport import Budget, ProbeClient


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI not installed; only local TLS integration tests skipped")
class LocalTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.cert, cls.key = cls.root / "cert.pem", cls.root / "key.pem"
        command = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                   "-keyout", str(cls.key), "-out", str(cls.cert), "-subj", "/CN=localhost",
                   "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"]
        subprocess.run(command, capture_output=True, check=True, timeout=15)
        cls.server = create_server(hardened=True)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.cert), str(cls.key))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = Target.parse(f"https://127.0.0.1:{cls.server.server_address[1]}/")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(3)
        cls.temp.cleanup()

    def test_untrusted_certificate_is_rejected_without_insecure_retry(self):
        scope = Scope.resolve(self.target, authorized=True, allow_private=True)
        probes = ProbeClient(scope, Budget())
        result = probes.tls()
        self.assertEqual(result["error"], "certificate_verification_failed")
        self.assertEqual(probes.budget.used, 1)

    def test_explicit_test_ca_enables_verified_tls_and_https(self):
        scope = Scope.resolve(self.target, authorized=True, allow_private=True)
        probes = ProbeClient(scope, Budget())
        real_context = ssl.create_default_context
        def trusted_context(*args, **kwargs):
            context = real_context(*args, **kwargs)
            context.load_verify_locations(cafile=str(self.cert))
            return context
        with patch("deepaudit.transport.ssl.create_default_context", side_effect=trusted_context):
            tls = probes.tls()
            http = probes.http()
        self.assertEqual(tls["status"], "ok")
        self.assertTrue(tls["verified"])
        self.assertIn("not_after", tls)
        self.assertEqual(http["status_code"], 200)
        self.assertTrue(http["signals"]["nosniff"])
