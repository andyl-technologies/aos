"""Exercise genuine Native upload refusal before offering a declared body.

Expect/100-continue measures actual wire behavior against the installed Native
TLS listener, bypassing only fixture observation buffering. It is not a body
poll counter or a provider permission proof. Every reply stays in a distinct
negative-scenario window, outside accepted publication byte/latency assertions.
"""

import json
import re
import shlex
from urllib.parse import urlsplit


def assert_direct_prebody_reply(observed, expected_status):
    """Require the real refusal and zero bytes offered by this actual curl call."""
    if (observed["exitCode"] != 0 or observed["timedOut"]
            or observed["status"] != expected_status or observed["offeredUploadBytes"] != 0
            or observed["continueReceived"] or observed["declaredBodyBytes"] <= 256 * 1024):
        raise AssertionError(observed)


def run_direct_native_prebody_probes(native, tools, helper):
    """Send missing/mismatched phase and oversized preflight controls to Native."""
    origin = urlsplit(tools["nativeOriginUrl"])
    public = urlsplit(tools["workerUrl"])
    if (origin.scheme != "https" or public.scheme != "https" or not origin.hostname
            or origin.path or origin.query or origin.fragment or origin.port not in {None, 443}
            or not public.netloc or public.path or public.query or public.fragment):
        raise ValueError("Native prebody scenario requires exact selected HTTPS origins")
    path = "/aos.hub.v1.BinaryCacheService/UploadObject/cache/ticket/bmFyL3g"
    root = "/var/lib/hybrid-shared-controls/prebody"
    payload = root + "/declared-payload"
    source = json.loads(direct_guest_python(native, tools["python"], """
        import hashlib, os
        from pathlib import Path

        root = Path(selected['root'])
        root.mkdir(mode=0o700)
        body = b'P' * (1024 * 1024 + 17)
        descriptor = os.open(selected['payload'], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps({'byteSize': len(body), 'sha256': hashlib.sha256(body).hexdigest()}))
    """, {"root": root, "payload": payload}))
    observations = []
    for label, signed, header, status in (
        ("missing-phase", None, None, 400),
        ("mismatched-phase", "preflight", "admit", 401),
        ("oversized-preflight", "preflight", "preflight", 413),
    ):
        destination = root + "/" + label
        prepared = run_direct_shared_control(native, tools, helper, {
            "kind": "ingress_prepare", "key_file": tools["nativeIngressKeyFile"],
            "deployment_id": tools["deploymentId"], "authority": public.netloc,
            "method": "PUT", "path_and_query": path, "body_file": payload,
            "signed_phase": signed, "header_phase": header, "output_directory": destination,
        }, "prebody-" + label)
        observation = json.loads(direct_guest_python(native, tools["python"], """
            import hashlib, os, re, subprocess, time
            from pathlib import Path

            root = Path(selected['directory'])
            for name in ('response.body', 'response.headers'):
                descriptor = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(descriptor)
            arguments = selected['curl'] + ['-sS', '--http1.1', '--max-time', '10',
                '--expect100-timeout', '20', '--max-filesize', '65536', '-X', 'PUT',
                '--connect-to', selected['connectTo'], '-H', '@' + str(root / 'headers.txt'),
                '-H', 'Expect: 100-continue', '--data-binary', '@' + selected['payload'],
                '-D', str(root / 'response.headers'), '-o', str(root / 'response.body'),
                '-w', '%{http_code}|%{size_upload}', selected['url']]
            started = time.time_ns()
            try:
                result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                    capture_output=True, check=False, timeout=15)
                stdout, stderr = result.stdout, result.stderr
                exit_code, timed_out = result.returncode, False
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b'', error.stderr or b''
                exit_code, timed_out = None, True
            headers = (root / 'response.headers').read_bytes()
            body = (root / 'response.body').read_bytes()
            if len(headers) > 16384 or len(body) > 65536:
                raise ValueError('Native refusal response exceeded selected observation bound')
            match = re.fullmatch(rb'([0-9]{3})\\|([0-9]+)', stdout)
            print(json.dumps({'version': 1, 'label': selected['label'],
                'exitCode': exit_code, 'timedOut': timed_out,
                'status': int(match[1]) if match else None,
                'offeredUploadBytes': int(match[2]) if match else None,
                'continueReceived': any(re.match(rb'HTTP/[0-9.]+ 100(?: |$)', line)
                    for line in headers.splitlines()),
                'declaredBodyBytes': os.stat(selected['payload']).st_size,
                'startedUnixNs': str(started), 'finishedUnixNs': str(time.time_ns()),
                'headersSha256': hashlib.sha256(headers).hexdigest(), 'headersBytes': len(headers),
                'bodySha256': hashlib.sha256(body).hexdigest(), 'bodyBytes': len(body),
                'stderrSha256': hashlib.sha256(stderr).hexdigest(), 'stderrBytes': len(stderr),
                'bodyFile': str(root / 'response.body'),
                'scope': 'actual Native TLS response before offering declared upload; not a body-poll counter'}))
        """, {"directory": destination, "curl": shlex.split(tools["curl"]),
            "payload": payload, "url": tools["nativeOriginUrl"] + path, "label": label,
            "connectTo": origin.hostname + ":443:127.0.0.1:4443"}, timeout=25))
        observation["preparedAssertionSha256"] = prepared["requestSha256"]
        observation["source"] = source
        observation["sharedCodecRevision"] = helper["codecRevision"]
        retain_direct_flow("actual-native-prebody-" + label + ".json", observation)
        observations.append(observation)
        assert_direct_prebody_reply(observation, status)
    return {"version": 1, "observations": observations,
        "scope": "separate actual Native upload-refusal wire window; no accepted-workload zero inference"}
