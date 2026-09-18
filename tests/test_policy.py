import socket
import unittest
from unittest.mock import patch
from deepaudit.policy import PolicyError, Scope, Target, validate_address


class TargetTests(unittest.TestCase):
    def test_bare_domain_defaults_to_https(self):
        self.assertEqual(Target.parse("Example.COM").url, "https://example.com/")

    def test_bare_ipv4(self):
        self.assertEqual(Target.parse("1.1.1.1").url, "https://1.1.1.1/")

    def test_bare_ipv6(self):
        self.assertEqual(Target.parse("2606:4700:4700::1111").url, "https://[2606:4700:4700::1111]/")

    def test_explicit_port_and_path(self):
        self.assertEqual(Target.parse("http://127.0.0.1:8080/health").url, "http://127.0.0.1:8080/health")

    def test_ipv6_port(self):
        self.assertEqual(Target.parse("http://[::1]:8080/").port, 8080)

    def test_idna(self):
        self.assertEqual(Target.parse("b\u00fccher.example").host, "xn--bcher-kva.example")

    def test_reject_bad_targets(self):
        for target in ("", " example.com", "file:///etc/passwd", "https://a:b@example.com/",
                       "https://example.com/?key=a", "https://example.com/#x", "https://example.com/?",
                       "http://[fe80::1%25eth0]/", "https://example.com/\n", "http://a/%0d%0aX:a",
                       "https://a:0/", "https://a:65536/", "http://bad_host/", "http://a\\b/"):
            with self.subTest(target=target), self.assertRaises(PolicyError):
                Target.parse(target)


class ScopeTests(unittest.TestCase):
    def test_public_ipv4_ipv6(self):
        for ip in ("1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"):
            self.assertEqual(validate_address(ip), ip)

    def test_private_needs_opt_in(self):
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.1.2", "::1", "fd00::1"):
            with self.subTest(ip=ip):
                with self.assertRaises(PolicyError):
                    validate_address(ip)
                self.assertEqual(validate_address(ip, True), ip)

    def test_special_addresses_always_blocked(self):
        for ip in ("169.254.169.254", "0.0.0.0", "224.0.0.1", "255.255.255.255", "100.64.0.1",
                   "fe80::1", "ff02::1", "::", "2002:7f00:1::"):
            for private in (False, True):
                with self.subTest(ip=ip, private=private), self.assertRaises(PolicyError):
                    validate_address(ip, private)

    def test_mapped_ipv4_does_not_bypass_policy(self):
        with self.assertRaises(PolicyError):
            validate_address("::ffff:127.0.0.1")
        self.assertEqual(validate_address("::ffff:127.0.0.1", True), "127.0.0.1")
        with self.assertRaises(PolicyError):
            validate_address("::ffff:169.254.169.254", True)

    @patch("deepaudit.policy.socket.getaddrinfo")
    def test_authorization_before_dns(self, resolver):
        with self.assertRaises(PolicyError):
            Scope.resolve(Target.parse("example.com"), authorized=False)
        resolver.assert_not_called()

    @patch("deepaudit.policy.socket.getaddrinfo")
    def test_mixed_resolution_fails_closed(self, resolver):
        resolver.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))
                                 for ip in ("1.1.1.1", "127.0.0.1")]
        with self.assertRaises(PolicyError):
            Scope.resolve(Target.parse("example.com"), authorized=True)

    @patch("deepaudit.policy.socket.getaddrinfo", side_effect=socket.gaierror())
    def test_dns_failure_is_controlled(self, resolver):
        with self.assertRaises(PolicyError):
            Scope.resolve(Target.parse("example.com"), authorized=True)

    @patch("deepaudit.policy.socket.getaddrinfo")
    def test_ip_literal_does_not_require_dns(self, resolver):
        result = Scope.resolve(Target.parse("1.1.1.1"), authorized=True)
        self.assertEqual(result.addresses, ("1.1.1.1",))
        resolver.assert_not_called()
