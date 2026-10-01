"""Observe real browser session revocation after the business traffic window.

Private request headers, cookies and every response stay on the client. These
terminal checks cover session authentication and private app-shell caching;
they do not establish separate instance IAM or provider grant expiry.
"""

import json
import shlex


DIRECT_BROWSER_SESSION_PROGRAM = r"""
import hashlib, json, os, re, stat, subprocess, time
from pathlib import Path

os.umask(0o077)
root = Path(selected['root'])
root.mkdir(mode=0o700, parents=True, exist_ok=False)
cookie = Path(selected['cookie'])
metadata = cookie.lstat()
if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077 or metadata.st_size > 65536):
    raise ValueError('selected browser cookie lacks private regular-file custody')
origin = 'https://aos.andyl.org'
observations = []

def private_file(name, body):
    descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    return root / name

def request(label, path, method='GET', authentication='anonymous', extra=(), payload=None):
    body = private_file(label + '.body', b'')
    headers = private_file(label + '.headers', b'')
    arguments = selected['curl'] + ['-sS', '--max-time', '20', '--max-filesize', '262144',
        '--request', method, '--output', str(body), '--dump-header', str(headers),
        '--write-out', '%{http_code}', '--header', 'cf-connecting-ip: 192.0.2.10']
    if authentication == 'cookie':
        arguments += ['--cookie', str(cookie)]
    elif authentication == 'bearer':
        arguments += ['--header', '@' + str(root / 'bearer.headers')]
    if payload is not None:
        arguments += ['--data-binary', '@' + str(private_file(label + '.request', payload))]
    arguments += list(extra) + [origin + path]
    started = time.time_ns()
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
        capture_output=True, check=False, timeout=25)
    captured, raw_headers = body.read_bytes(), headers.read_bytes()
    if len(captured) > 262144 or len(raw_headers) > 65536:
        raise ValueError('browser response exceeded its selected body/header bounds')
    status = int(result.stdout) if len(result.stdout) == 3 and result.stdout.isdigit() else None
    locations = re.findall(rb'(?im)^location:\s*([^\r\n]+)', raw_headers)
    observed = {'version': 1, 'label': label, 'path': path, 'method': method,
        'authentication': authentication, 'status': status, 'exitCode': result.returncode,
        'startedUnixNs': str(started), 'completedUnixNs': str(time.time_ns()),
        'bodySha256': hashlib.sha256(captured).hexdigest(), 'bodyBytes': len(captured),
        'headersSha256': hashlib.sha256(raw_headers).hexdigest(), 'headersBytes': len(raw_headers),
        'stderrSha256': hashlib.sha256(result.stderr).hexdigest(), 'stderrBytes': len(result.stderr),
        'redirectsToLogin': locations == [b'/login']}
    observations.append(observed)
    private_file(label + '.observation.json', json.dumps(observed, sort_keys=True).encode())
    if result.returncode or result.stderr or status is None:
        raise RuntimeError('browser transport is unknown; private originals retained')
    return observed, captured

try:
    warm, html = request('warm-private', '/-/instance', authentication='cookie')
    if warm['status'] != 200:
        raise ValueError('actual warm browser session was refused')
    csrf = re.findall(rb'name="aos-session-csrf" content="([0-9a-f]{64})"', html)
    if len(csrf) != 1:
        raise ValueError('actual warm app shell has no unique bounded CSRF value')
    request('public-before', '/_assets/style.css')
    request('missing-csrf', '/-/auth/session-token', 'POST', 'cookie',
        ['--header', 'Origin: ' + origin])
    token_headers = private_file('token.headers', b'Origin: ' + origin.encode()
        + b'\nx-aos-csrf: ' + csrf[0] + b'\nx-aos-console-route: /-/instance\n')
    minted, raw_token = request('minted-token', '/-/auth/session-token', 'POST', 'cookie',
        ['--header', '@' + str(token_headers)])
    if minted['status'] != 200:
        raise ValueError('genuine browser bearer issuance was refused')
    token = json.loads(raw_token)
    bearer = token['accessToken']
    if (token['tokenType'] != 'Bearer' or int(token['expiresIn']) != 300
            or not isinstance(bearer, str) or len(bearer) > 32768
            or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', bearer)):
        raise ValueError('actual session-token reply differs from its bounded bearer contract')
    private_file('bearer.headers', ('Authorization: Bearer ' + bearer
        + '\nContent-Type: application/json\nConnect-Protocol-Version: 1\n').encode())
    request('bearer-before', '/aos.hub.v1.IdentityService/WhoAmI', 'POST', 'bearer', payload=b'{}')
    request('logout', '/logout', 'POST', 'cookie',
        ['--header', 'Content-Type: application/x-www-form-urlencoded'], b'csrf=' + csrf[0])
    request('bearer-after', '/aos.hub.v1.IdentityService/WhoAmI', 'POST', 'bearer', payload=b'{}')
    # Keep the original cookie file unchanged: logout's Set-Cookie does not
    # erase the credential whose server-side revocation this request proves.
    request('cookie-after', '/-/instance', authentication='cookie')
    request('anonymous-private', '/-/instance')
    request('anonymous-token', '/-/auth/session-token', 'POST', extra=['--header', 'Origin: ' + origin])
    request('public-after', '/_assets/style.css')
    print(json.dumps({'version': 1, 'observations': observations,
        'scope': 'actual browser session authentication/cache checks; no instance IAM or provider grant claim'}))
finally:
    private_file('observations.json', json.dumps(observations, sort_keys=True).encode())
"""


def assert_direct_browser_session(observed):
    """Require current session denial and exact public asset continuity."""
    rows = observed["observations"]
    expected = {
        "warm-private": 200, "public-before": 200, "missing-csrf": 403,
        "minted-token": 200, "bearer-before": 200, "logout": 303,
        "bearer-after": 403, "cookie-after": 303, "anonymous-private": 303,
        "anonymous-token": 401, "public-after": 200,
    }
    if len(rows) != len(expected) or [row["label"] for row in rows] != list(expected):
        raise ValueError("browser observations are missing, duplicated or reordered")
    for row in rows:
        if row["status"] != expected[row["label"]] or row["exitCode"] or row["stderrBytes"]:
            raise ValueError("actual browser response differs from the required session scenario")
        if row["label"] in {"logout", "cookie-after", "anonymous-private"} and not row["redirectsToLogin"]:
            raise ValueError("actual private session refusal did not redirect to login")
    before, after = rows[1], rows[-1]
    if not before["bodyBytes"] or (before["bodyBytes"], before["bodySha256"]) != (
            after["bodyBytes"], after["bodySha256"]):
        raise ValueError("public static asset changed during the session refusal window")


def run_direct_browser_session(client, native, worker, tools, process):
    """Capture a terminal session window after all remaining root operations."""
    native_position = direct_log_position(native, tools["python"],
        "/var/lib/hybrid-native-observations/requests.jsonl")
    worker_position = direct_log_position(worker, tools["python"], process["logFile"])
    result = {"version": 1, "nativeBulkBytes": None, "observations": [],
        "scope": "separate terminal browser refusal window; all private bodies retained, no zero inference"}
    try:
        result.update(json.loads(direct_guest_python(client, tools["python"],
            DIRECT_BROWSER_SESSION_PROGRAM, {"curl": shlex.split(tools["curl"]),
                "root": "/var/lib/hybrid-client/browser-refusals",
                "cookie": "/var/lib/hybrid-client/browser-session/cookies"}, timeout=320)))
        retain_direct_flow("browser-session-observations.json", result)
        assert_direct_browser_session(result)
    finally:
        _, result["nativeLogWindow"] = retain_direct_log_window(native, tools["python"],
            native_position, "browser-native.jsonl")
        _, result["workerLogWindow"] = retain_direct_log_window(worker, tools["python"],
            worker_position, "browser-worker.log")
        result["privateObservationFile"] = "/var/lib/hybrid-client/browser-refusals/observations.json"
        retain_direct_flow("actual-browser-refusal-window.json", result)
    return result
