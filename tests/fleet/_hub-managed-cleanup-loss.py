"""Lose one completed, Rust-authenticated cleanup reply in a confined fixture.

The listener is selected in the initial Native outbound proxy configuration.
It forwards bounded metadata to the actual TLS Worker. It creates no object,
claim or reply; ordinary errors cannot satisfy deliberate completed-response loss.
"""

import argparse
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import selectors
from pathlib import Path
import socket
import ssl
import stat
import struct
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


ROUTE = "/_internal/storage/managed-oci-cleanup/v1"
SIGNATURE = "x-aos-managed-oci-cleanup-signature"
CORRELATION_HEADERS = ("x-aos-fleet-request-id", "x-aos-storage-call-id")
TEST = "storage_work::oci_cleanup::controlled::actual_managed_terminal_cleanup_pair"
BOUND = 16384
MAX_EXCHANGES = 32
AUTHENTICATION_OUTPUT_BOUND = 65536


def closed(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate cleanup transport field")
        value[name] = item
    return value


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def private_bytes(path, bound):
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError("cleanup custody path differs")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size > bound):
            raise ValueError("cleanup file custody differs")
        body = stream.read(bound + 1)
        after = os.fstat(stream.fileno())
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns)
    if len(body) > bound or identity(before) != identity(after) or identity(before) != identity(path.lstat()):
        raise ValueError("cleanup file changed during collection")
    return body


def retain(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    return {"path": str(path), "sha256": hashlib.sha256(body).hexdigest(), "byteSize": len(body)}


def validate_arm(arm, body, now):
    if (set(arm) != {"version", "originalSha256", "protectedProfileDigest", "helperInput", "expiresAt"}
            or arm["version"] != 1 or type(arm["expiresAt"]) is not int or now >= arm["expiresAt"]):
        raise ValueError("cleanup arm is stale or malformed")
    request = json.loads(body, object_pairs_hook=closed)
    if (hashlib.sha256(encode(request["original"])).hexdigest() != arm["originalSha256"]
            or request["protected_profile_digest"] != arm["protectedProfileDigest"]
            or type(request["issued_at"]) is not int or type(request["expires_at"]) is not int
            or not 0 < request["expires_at"] - request["issued_at"] <= 30
            or request["expires_at"] > arm["expiresAt"]
            or request["issued_at"] > now or now >= request["expires_at"]):
        raise ValueError("cleanup request differs from the once-only SQL/profile arm")
    return request


def collect_authentication_output(process, timeout):
    """Collect bounded actual pipe prefixes; overflow cannot establish custody."""
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = {"stdout": False, "stderr": False}
    stop = time.monotonic() + timeout
    failure = None
    with selectors.DefaultSelector() as selected:
        for name in buffers:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selected.register(stream, selectors.EVENT_READ, name)
        while selected.get_map():
            if time.monotonic() >= stop:
                failure = "OutputTimeout"
                if process.poll() is None:
                    process.kill()
                break
            for key, _ in selected.select(min(0.05, max(0, stop - time.monotonic()))):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selected.unregister(key.fileobj)
                    continue
                name = key.data
                remaining = AUTHENTICATION_OUTPUT_BOUND - len(buffers[name])
                buffers[name].extend(block[:remaining])
                if len(block) > remaining:
                    overflow[name] = True
                    failure = "OutputOverflow"
                    if process.poll() is None:
                        process.kill()
        try:
            process.wait(timeout=max(0.001, stop - time.monotonic()))
        except subprocess.TimeoutExpired:
            failure = "OutputTimeout"
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
    return {name: bytes(body) for name, body in buffers.items()}, overflow, failure


def observe_authentication_process(configuration, root, input_ref, arguments, environment):
    """Retain a separate owned upstream-only helper lifetime and actual outputs."""
    runtime_path = Path(__file__).with_name("_hub-managed-cleanup-runtime.py")
    specification = importlib.util.spec_from_file_location("cleanup_authentication_custody", runtime_path)
    runtime = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(runtime)
    started = {"unixNs": str(time.time_ns()), "monotonicNs": str(time.monotonic_ns())}
    nonce = secrets.token_hex(16)
    environment = dict(environment, AOS_MANAGED_CLEANUP_STARTUP_ROOT=str(root),
                       AOS_MANAGED_CLEANUP_STARTUP_NONCE=nonce)
    process = subprocess.Popen(arguments, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pin = None
    failure = None
    ready_ref = None
    release_ref = None
    buffers = {"stdout": b"", "stderr": b""}
    overflow = {"stdout": False, "stderr": False}
    collection_complete = False
    try:
        stop = time.monotonic() + 10
        ready_path = root / "authentication-ready.private.json"
        while not ready_path.exists():
            if process.poll() is not None or time.monotonic() >= stop:
                raise ValueError("cleanup authenticator did not wait for live pinning")
            time.sleep(0.01)
        ready_bytes = private_bytes(ready_path, 1024)
        ready = json.loads(ready_bytes, object_pairs_hook=closed)
        if (set(ready) != {"version", "nonce", "pid", "scope"} or ready["version"] != 1
                or ready["nonce"] != nonce or ready["pid"] != process.pid
                or ready["scope"] != "managed_cleanup_before_input"):
            raise ValueError("cleanup authenticator readiness differs")
        ready_ref = {"path": str(ready_path), "sha256": hashlib.sha256(ready_bytes).hexdigest(),
                     "byteSize": len(ready_bytes)}
        pin = runtime.helper_process(process, root, configuration["nativeHelperSha256"])
        writing = root / "authentication-release-writing.private.json"
        release_ref = retain(writing, encode({"version": 1, "nonce": nonce}))
        released = root / "authentication-release.private.json"
        if os.path.lexists(released):
            raise ValueError("cleanup authenticator release already exists")
        os.rename(writing, released)
        release_ref["path"] = str(released)
        buffers, overflow, capture_failure = collect_authentication_output(process, 30)
        collection_complete = capture_failure is None
        failure = capture_failure
    except BaseException as error:
        # This exact owned child is the read-only upstream validator. Its
        # consumption is never the original Native dispatch's consumption.
        failure = type(error).__name__
        if process.poll() is None:
            process.kill()
        try:
            buffers, overflow, _ = collect_authentication_output(process, 3)
        except Exception:
            # A pipe held by an unexpected child remains an incomplete lifetime.
            collection_complete = False
    finished = {"unixNs": str(time.time_ns()), "monotonicNs": str(time.monotonic_ns())}
    process.stdout.close()
    process.stderr.close()
    stdout_ref = retain(root / "authentication.stdout", buffers["stdout"])
    stderr_ref = retain(root / "authentication.stderr", buffers["stderr"])
    output_ref = None
    output_error = None
    try:
        output_path = root / "authenticated.json"
        if output_path.exists():
            output = private_bytes(output_path, 65536)
            output_ref = {"path": str(output_path), "sha256": hashlib.sha256(output).hexdigest(),
                          "byteSize": len(output)}
    except Exception as error:
        output_error = type(error).__name__
    invocation = {"version": 1, "scope": "managed_cleanup_upstream_authentication_helper",
        "phase": "authenticate_lost_reply", "transportScope": "read_only_upstream_validation",
        "nativeTransportObservation": None, "helperProcess": pin, "arguments": arguments,
        "input": input_ref, "output": output_ref, "outputErrorKind": output_error,
        "started": started, "finished": finished,
        "stdout": stdout_ref, "stderr": stderr_ref, "exitCode": process.returncode,
        "failureKind": failure, "completeProcessCustody": pin is not None and failure is None,
        "startupReady": ready_ref, "startupRelease": release_ref,
        "outputBound": AUTHENTICATION_OUTPUT_BOUND, "outputOverflow": overflow,
        "completeOutputCollection": collection_complete,
        "listenerSourceSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "runtimeSourceSha256": hashlib.sha256(runtime_path.read_bytes()).hexdigest()}
    invocation_ref = retain(root / "authentication-invocation.private.json", encode(invocation))
    return invocation_ref, invocation


def authenticate_completion(configuration, arm, root, request_body, request_signature,
                            reply_body, reply_signature):
    """Invoke the selected Native helper's read-only production MAC validators."""
    files = {}
    for name, body in (("request", request_body), ("request-signature", request_signature.encode()),
                       ("reply", reply_body), ("reply-signature", reply_signature.encode())):
        files[name] = retain(root / (name + ".private"), body)
    selected = {**arm["helperInput"], "phase": "authenticate_lost_reply",
        "outputFile": str(root / "authenticated.json"),
        "lostRequestFile": files["request"]["path"],
        "lostRequestSignatureFile": files["request-signature"]["path"],
        "lostReplyFile": files["reply"]["path"],
        "lostReplySignatureFile": files["reply-signature"]["path"]}
    input_path = root / "authentication-input.json"
    input_ref = retain(input_path, encode(selected))
    executable = Path(configuration["nativeHelper"])
    if hashlib.sha256(executable.read_bytes()).hexdigest() != configuration["nativeHelperSha256"]:
        raise ValueError("selected cleanup helper changed")
    environment = dict(os.environ, AOS_MANAGED_CLEANUP_CONTROLLED_INPUT=str(input_path))
    arguments = [str(executable), TEST, "--exact", "--ignored", "--nocapture"]
    invocation_ref, invocation = observe_authentication_process(
        configuration, root, input_ref, arguments, environment)
    if (invocation["failureKind"] is not None or not invocation["completeProcessCustody"]
            or invocation["exitCode"] != 0):
        raise ValueError("actual completed cleanup reply failed Rust authentication")
    proof = json.loads(private_bytes(root / "authenticated.json", 65536), object_pairs_hook=closed)
    if (proof["outcome"] != "authenticated_completed_response"
            or proof["originalSha256"] != arm["originalSha256"]
            or proof["protectedProfileDigest"] != arm["protectedProfileDigest"]
            or proof["authenticatedRequestSha256"] != hashlib.sha256(request_body).hexdigest()
            or not proof["sqlClaimUnchangedAfterAttempt"] or proof["physicalReply"] is None
            or proof.get("nativeExchangeObservations") is not None):
        raise ValueError("Rust completed-response proof differs from actual transport")
    return {"files": files, "proof": proof, "invocation": invocation_ref,
        "helperProcess": invocation,
        "proofFile": {"path": str(root / "authenticated.json"),
            "sha256": hashlib.sha256((root / "authenticated.json").read_bytes()).hexdigest()}}


class CleanupServer(HTTPServer):
    def __init__(self, configuration):
        self.configuration = configuration
        self.root = Path(configuration["root"])
        self.consumed = False
        self.sequence = 0
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ca = Path(configuration["caFile"]).read_bytes()
        if hashlib.sha256(ca).hexdigest() != configuration["caSha256"]:
            raise ValueError("selected cleanup TLS root changed")
        self.context.load_verify_locations(cadata=ca.decode("ascii"))
        super().__init__(("127.0.0.1", 4660), CleanupHandler)


def upstream_connection(configuration, context):
    """Connect only to the initially selected Worker with strict localhost TLS."""
    raw = socket.create_connection((configuration["workerAddress"], 4643), timeout=30)
    tls = context.wrap_socket(raw, server_hostname="localhost")
    certificate_sha256 = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    upstream = http.client.HTTPConnection("localhost", 4643, timeout=30)
    upstream.sock = tls
    return upstream, certificate_sha256


class CleanupHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *arguments):
        pass

    def do_POST(self):
        server = self.server
        config = server.configuration
        server.sequence += 1
        if server.sequence > MAX_EXCHANGES:
            self.close_connection = True
            self.connection.close()
            return
        root = server.root / ("exchange-%04d" % server.sequence)
        root.mkdir(mode=0o700, exist_ok=False)
        receipt = {"version": 1, "outcome": "unknown", "startedUnixNs": time.time_ns()}
        upstream = None
        try:
            self.connection.settimeout(35)
            if self.path != ROUTE or self.headers.get_all("Transfer-Encoding"):
                raise ValueError("cleanup listener accepts only its selected metadata route")
            sizes = self.headers.get_all("Content-Length", [])
            signatures = self.headers.get_all(SIGNATURE, [])
            if len(sizes) != 1 or not sizes[0].isdecimal() or not 0 < int(sizes[0]) <= BOUND or len(signatures) != 1:
                raise ValueError("cleanup request framing or signature differs")
            hosts = self.headers.get_all("Host", [])
            if len(hosts) != 1 or hosts[0] not in ("localhost", "localhost:4643"):
                raise ValueError("cleanup configured origin Host differs")
            forwarding_headers = {"Host": hosts[0], "Content-Type": "application/json",
                                  "Content-Length": sizes[0], SIGNATURE: signatures[0]}
            for name in CORRELATION_HEADERS:
                values = self.headers.get_all(name, [])
                if len(values) > 1 or (values and (not re.fullmatch(r'[0-9a-f]{32}', values[0]))):
                    raise ValueError("cleanup non-authorizing correlation header differs")
                if values:
                    forwarding_headers[name] = values[0]
            body = self.rfile.read(int(sizes[0]))
            if len(body) != int(sizes[0]):
                raise ValueError("cleanup request body is incomplete")
            request_ref = retain(root / "offered-body.private", body)
            arm_path = Path(config["armFile"])
            arm = None
            if arm_path.exists() and not server.consumed:
                arm = json.loads(private_bytes(arm_path, 65536), object_pairs_hook=closed)
                validate_arm(arm, body, int(time.time()))
                server.consumed = True
                retain(server.root / "arm-consumed.json", encode({"requestSha256": request_ref["sha256"],
                    "originalSha256": arm["originalSha256"], "exchange": str(root)}))
            upstream, certificate_sha256 = upstream_connection(config, server.context)
            upstream.request("POST", ROUTE, body=body, headers=forwarding_headers)
            response = upstream.getresponse()
            reply = response.read(BOUND + 1)
            if len(reply) > BOUND:
                raise ValueError("cleanup reply exceeds metadata bound")
            reply_ref = retain(root / "received-body.private", reply)
            reply_signatures = [value for name, value in response.getheaders() if name.lower() == SIGNATURE]
            receipt.update(request=request_ref, reply=reply_ref, status=response.status,
                forwardedHost=hosts[0], correlationHeaders={name:forwarding_headers[name]
                    for name in CORRELATION_HEADERS if name in forwarding_headers},
                tlsPeerCertificateSha256=certificate_sha256)
            receipt['requestSignature'] = retain(root / 'offered-signature.private', signatures[0].encode())
            if len(reply_signatures) == 1:
                receipt['replySignature'] = retain(root / 'received-signature.private', reply_signatures[0].encode())
            if arm is not None:
                if response.status != 200 or len(reply_signatures) != 1:
                    raise ValueError("generic upstream refusal is not completed-response loss")
                authentication = authenticate_completion(config, arm, root, body, signatures[0], reply, reply_signatures[0])
                receipt.update(outcome="authenticated_completed_response_deliberately_lost", authentication=authentication)
                retain(root / "before-deliberate-close.json", encode(receipt))
                # A complete positively authenticated upstream response already
                # exists. No byte of that response is sent to the downstream.
                self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                self.connection.close()
                self.close_connection = True
            else:
                self.send_response(response.status)
                self.send_header("Content-Length", str(len(reply)))
                self.send_header("Connection", "close")
                if len(reply_signatures) == 1:
                    self.send_header(SIGNATURE, reply_signatures[0])
                self.end_headers()
                self.wfile.write(reply)
                self.close_connection = True
                receipt["outcome"] = "ordinary_forwarded_response"
        except Exception as error:
            receipt["errorKind"] = type(error).__name__
            self.close_connection = True
            try:
                self.connection.close()
            except OSError:
                pass
        finally:
            if upstream is not None:
                upstream.close()
            receipt["finishedUnixNs"] = time.time_ns()
            retain(root / "exchange.json", encode(receipt))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", required=True)
    args = parser.parse_args()
    configuration_bytes = private_bytes(args.configuration, 65536)
    config = json.loads(configuration_bytes, object_pairs_hook=closed)
    expected = {"version", "root", "workerAddress", "caFile", "caSha256", "nativeHelper", "nativeHelperSha256", "armFile"}
    if set(config) != expected or config["version"] != 1:
        raise ValueError("cleanup initial configuration differs")
    address = ipaddress.ip_address(config["workerAddress"])
    if address.version != 4 or address.is_loopback or not address.is_private:
        raise ValueError("cleanup upstream must be the selected separate Worker VM")
    root = Path(config["root"])
    metadata = root.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700 or root.resolve() != root):
        raise ValueError("cleanup initial evidence root differs")
    executable = Path(config["nativeHelper"])
    with executable.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != config["nativeHelperSha256"]:
            raise ValueError("cleanup initial helper differs")
    with CleanupServer(config) as server:
        # HTTPServer has already bound and activated the fixed listener. This
        # is an observed readiness fact, separate from a live process PID.
        process = Path("/proc/self")
        start_ticks = (process / "stat").read_text().rpartition(") ")[2].split()[19]
        retain(root / "ready.json", encode({
            "version": 1, "scope": "managed_terminal_cleanup_loss_listener",
            "pid": os.getpid(), "startTicks": start_ticks, "ownerUid": process.stat().st_uid,
            "configurationSha256": hashlib.sha256(configuration_bytes).hexdigest(),
            "listenerSourceSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "listenAddress": "127.0.0.1:4660", "route": ROUTE,
        }))
        server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
