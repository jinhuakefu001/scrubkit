#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal test suite: python -m unittest discover -s tests"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scrubkit import entropy, is_noise, load_rules, scan_text, scrub_text  # noqa: E402


class TestEntropy(unittest.TestCase):
    def test_charset_has_low_relative_structure(self):
        self.assertGreater(entropy('ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 3.5)

    def test_repeated_char_is_zero(self):
        self.assertEqual(entropy('aaaaaaaa'), 0.0)


class TestNoiseFilter(unittest.TestCase):
    def test_charset_literal(self):
        self.assertTrue(is_noise('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='))

    def test_placeholder(self):
        self.assertTrue(is_noise('YOUR_API_KEY'))
        self.assertTrue(is_noise('REPLACE_WITH_TOKEN'))

    def test_template_expression(self):
        self.assertTrue(is_noise("password === 'password'"))
        self.assertTrue(is_noise('${DB_PASSWORD}'))
        self.assertTrue(is_noise('{{ user.token }}'))

    def test_real_key_is_not_noise(self):
        self.assertFalse(is_noise('sk-proj-a1b2C3d4E5f6G7h8I9j0K1l2M3n4'))


class TestScan(unittest.TestCase):
    def setUp(self):
        self.cfg = load_rules(use_entropy=True)

    def _rules(self, text):
        return {f['rule'] for f in scan_text(text, self.cfg)}

    def test_aws_key(self):
        self.assertIn('aws-access-key-id',
                      self._rules('aws_key = "AKIAZ7Q2XK9M3P8V4TWQ"'))

    def test_github_token(self):
        self.assertIn('github-token',
                      self._rules('token: ghp_' + 'a' * 36))

    def test_php_define(self):
        self.assertIn('define-key',
                      self._rules("define('PAYMENT_SECRET_KEY', 'k3Yv4luE9xQ2mN8p');"))

    def test_php_array_arrow(self):
        self.assertIn('array-key-arrow',
                      self._rules("'api_secret' => 'k3Yv4luE9xQ2mN8pQr';"))

    def test_private_key_block(self):
        sample = ('-----BEGIN RSA PRIVATE KEY-----\n'
                  + 'MIIEow' * 40 + '\n-----END RSA PRIVATE KEY-----')
        self.assertIn('private-key-block', self._rules(sample))

    def test_dsn_with_password(self):
        self.assertIn('db-dsn-with-credentials',
                      self._rules('mysql://app:Xy9mQ2p@db.internal:3306/app'))

    def test_dsn_documentation_is_ignored(self):
        self.assertNotIn('db-dsn-with-credentials',
                         self._rules('mysql://username:password@localhost/db'))

    def test_jwt(self):
        jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123XYZ_-abc'
        self.assertIn('jwt', self._rules(jwt))


class TestScrub(unittest.TestCase):
    def setUp(self):
        self.cfg = load_rules(use_entropy=False)

    def test_placeholder_keeps_structure(self):
        src = "$key = 'sk-" + 'a1B2c3D4' * 5 + "';"
        out, n = scrub_text(src, self.cfg)
        self.assertEqual(n, 1)
        self.assertIn('$key = ', out)
        self.assertIn('OPENAI_API_KEY_EXAMPLE', out)
        self.assertTrue(out.rstrip().endswith(';'))

    def test_idempotent(self):
        src = "api_key = 'sk-" + 'a1B2c3D4' * 5 + "'"
        once, _ = scrub_text(src, self.cfg)
        twice, n2 = scrub_text(once, self.cfg)
        self.assertEqual(n2, 0)
        self.assertEqual(once, twice)

    def test_php_define_rewritten(self):
        src = "define('DYNADOT_API_KEY', '9U726X8k7V6n9I6c6L56T6l6a6te6kU');"
        out, n = scrub_text(src, self.cfg)
        self.assertEqual(n, 1)
        self.assertNotIn('9U726X8k7V6n9I6c6', out)


class TestEndToEnd(unittest.TestCase):
    def test_scan_scrub_verify_cycle(self):
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, 'config.py')
            with open(fp, 'w', encoding='utf-8') as f:
                f.write('AWS_ACCESS_KEY_ID = "AKIAZ7Q2XK9M3P8V4TWQ"\n')
                f.write('normal_value = "hello world"\n')

            cfg = load_rules(use_entropy=False)
            with open(fp, encoding='utf-8') as f:
                txt = f.read()

            findings = scan_text(txt, cfg)
            self.assertEqual(len(findings), 1)

            new, n = scrub_text(txt, cfg)
            self.assertEqual(n, 1)
            self.assertIn('normal_value', new)

            with open(fp, 'w', encoding='utf-8') as f:
                f.write(new)
            with open(fp, encoding='utf-8') as f:
                self.assertEqual(scan_text(f.read(), cfg), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
