"""Check browser probe custody and assertions with controlled HTTP peers.

The guest program executes against a local subprocess stand-in. These tests
establish source behavior only; no session or runtime cache is qualified.
"""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch


specification = importlib.util.spec_from_file_location("browser",
    Path(__file__).with_name("_hub-direct-browser.py"))
browser = importlib.util.module_from_spec(specification)
specification.loader.exec_module(browser)


class BrowserSessionProbe(unittest.TestCase):
    def run_peer(self):
        expected = {"warm-private": 200, "public-before": 200, "missing-csrf": 403,
            "minted-token": 200, "bearer-before": 200, "logout": 303,
            "bearer-after": 403, "cookie-after": 303, "anonymous-private": 303,
            "anonymous-token": 401, "public-after": 200}
        arguments = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "observations"
            cookie = Path(directory) / "cookies"
            cookie.write_bytes(b"controlled cookie")
            cookie.chmod(0o600)
            def run(argv, **options):
                arguments.append(argv)
                self.assertNotIn('-L', argv)
                self.assertNotIn('--location', argv)
                body = Path(argv[argv.index('--output') + 1])
                headers = Path(argv[argv.index('--dump-header') + 1])
                label = body.name.removesuffix('.body')
                status = expected[label]
                response = b'controlled reply'
                if label == 'warm-private':
                    response = b'<meta name="aos-session-csrf" content="' + b'a' * 64 + b'">'
                elif label == 'minted-token':
                    response = json.dumps({'accessToken': 'abc.def.ghi',
                        'tokenType': 'Bearer', 'expiresIn': 300}).encode()
                elif label.startswith('public-'):
                    response = b'controlled public stylesheet'
                body.write_bytes(response)
                headers.write_bytes(b'HTTP/1.1 ' + str(status).encode() + b' peer\r\n'
                    + (b'location: /login\r\n' if status == 303 else b'') + b'\r\n')
                return subprocess.CompletedProcess(argv, 0, str(status).encode(), b'')
            namespace = {'selected': {'root': str(root), 'cookie': str(cookie), 'curl': ['controlled-curl']}}
            with patch.object(subprocess, 'run', run), patch('builtins.print') as output:
                exec(compile(textwrap.dedent(browser.DIRECT_BROWSER_SESSION_PROGRAM),
                    'controlled-guest', 'exec'), namespace)
            result = json.loads(output.call_args.args[0])
            observations = json.loads((root / 'observations.json').read_bytes())
            self.assertEqual(result['observations'], observations)
            for item in root.iterdir():
                self.assertEqual(item.stat().st_mode & 0o777, 0o600)
            self.assertEqual(cookie.read_bytes(), b'controlled cookie')
            bearer = (root / 'bearer.headers').read_bytes()
            self.assertIn(b'Authorization: Bearer abc.def.ghi', bearer)
            self.assertNotIn('abc.def.ghi', json.dumps(result))
            self.assertTrue(all('abc.def.ghi' not in value for argv in arguments for value in argv))
            labels = [Path(argv[argv.index('--output') + 1]).name.removesuffix('.body') for argv in arguments]
            selected = dict(zip(labels, arguments))
            self.assertNotIn('--cookie', selected['anonymous-private'])
            self.assertNotIn('--cookie', selected['anonymous-token'])
            self.assertEqual(selected['cookie-after'][selected['cookie-after'].index('--cookie') + 1], str(cookie))
            self.assertNotIn('x-aos-csrf:', ' '.join(selected['missing-csrf']))
            self.assertEqual((root / 'logout.request').read_bytes(), b'csrf=' + b'a' * 64)
        return result

    def test_guest_uses_original_cookie_and_private_header_files(self):
        browser.assert_direct_browser_session(self.run_peer())

    def test_cached_private_success_and_missing_or_ambiguous_observations_refuse(self):
        actual = self.run_peer()
        for label in ('cookie-after', 'anonymous-private', 'bearer-after', 'missing-csrf'):
            altered = copy.deepcopy(actual)
            next(row for row in altered['observations'] if row['label'] == label)['status'] = 200
            with self.assertRaises(ValueError):
                browser.assert_direct_browser_session(altered)
        for rows in (actual['observations'][:-1], actual['observations'] + actual['observations'][:1],
                     list(reversed(actual['observations']))):
            with self.assertRaises(ValueError):
                browser.assert_direct_browser_session({'observations': rows})

    def test_redirect_transport_or_public_asset_change_refuses(self):
        actual = self.run_peer()
        for label, field, value in (('logout', 'redirectsToLogin', False),
                                    ('warm-private', 'stderrBytes', 1),
                                    ('bearer-after', 'exitCode', 28),
                                    ('public-after', 'bodySha256', 'b' * 64)):
            altered = copy.deepcopy(actual)
            next(row for row in altered['observations'] if row['label'] == label)[field] = value
            with self.assertRaises(ValueError):
                browser.assert_direct_browser_session(altered)

    def test_cookie_custody_refuses_before_http(self):
        with tempfile.TemporaryDirectory() as directory:
            cookie = Path(directory) / 'cookies'
            cookie.write_bytes(b'controlled cookie')
            cookie.chmod(0o644)
            selected = {'root': str(Path(directory) / 'new'), 'cookie': str(cookie), 'curl': ['controlled']}
            with patch.object(subprocess, 'run') as transport, self.assertRaises(ValueError):
                exec(compile(textwrap.dedent(browser.DIRECT_BROWSER_SESSION_PROGRAM),
                    'controlled-guest', 'exec'), {'selected': selected})
            transport.assert_not_called()


if __name__ == '__main__':
    unittest.main()
