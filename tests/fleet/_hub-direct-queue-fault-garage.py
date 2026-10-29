"""One real SigV4 Garage replacement through a selected source-built curl.

This owner-only adapter does not generate a verification response. The caller
must hold the exact production GET before forwarding it, then release that
unchanged request in finally. A readable pinned old version is unavailable for
this fault. Provider authentication/consumer outcomes remain independent.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from urllib.parse import quote, urlencode, urlsplit


MAX_OBJECT = 32 * 1024 * 1024
MAX_REPLY = 64 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _private_file(path, maximum):
    path = Path(path)
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
            or parent.st_mode & 0o077 or path.parent.resolve() != path.parent):
        raise ValueError("Garage adapter input parent is not private")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or before.st_nlink != 1
                or not 0 < before.st_size <= maximum):
            raise ValueError("Garage adapter input custody differs")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            body = stream.read(maximum + 1)
        after = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or len(body) != before.st_size):
            raise ValueError("Garage adapter input changed")
        return body
    finally:
        os.close(descriptor)


def _create(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())


class GarageSigV4:
    """Use real curl AWS signing; credentials enter only its private stdin.

    Fixed origin/bucket/key and private output names are selected once. This is
    instrumentation traffic, never an application SDK receipt or provider lease.
    """

    def __init__(self, curl, origin, region, credentials_file, directory, cutoff_ms):
        selected = urlsplit(origin)
        if (not curl.startswith("/nix/store/") or not curl.endswith("/bin/curl")
                or selected.scheme not in {"http", "https"} or not selected.hostname
                or selected.username or selected.password or selected.path
                or selected.query or selected.fragment
                or selected.scheme == "http" and selected.hostname != "127.0.0.1"
                or not re.fullmatch(r"[a-z0-9-]{1,32}", region)
                or type(cutoff_ms) is not int or cutoff_ms <= int(time.time() * 1000)):
            raise ValueError("Garage transport selection differs")
        self.directory = Path(directory)
        parent = self.directory.parent.lstat()
        if (self.directory.parent.resolve() != self.directory.parent
                or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or parent.st_mode & 0o077):
            raise ValueError("Garage transport output parent differs")
        self.directory.mkdir(mode=0o700)
        self.curl, self.origin, self.region = curl, origin, region
        self.credentials_file, self.cutoff_ms = credentials_file, cutoff_ms
        self.sequence = 0
        self.records = []

    def exchange(self, method, bucket, key, *, version=None, if_match=None, body=None):
        if (method not in {"HEAD", "GET", "PUT"}
                or not re.fullmatch(r"[a-z0-9-]{3,63}", bucket)
                or not isinstance(key, str) or not 0 < len(key.encode()) <= 1024
                or any(part in {"", ".", ".."} for part in key.split("/"))
                or any(ord(value) < 32 for value in key)
                or version is not None and (not isinstance(version, str) or not 0 < len(version) <= 1024)
                or if_match is not None and not re.fullmatch(r'"[A-Za-z0-9_-]{1,128}"', if_match)
                or method == "PUT" and (not isinstance(body, bytes) or not 0 < len(body) <= MAX_OBJECT)
                or method != "PUT" and body is not None):
            raise ValueError("Garage exchange is outside the selected bounded methods")
        remaining = (self.cutoff_ms - int(time.time() * 1000)) / 1000
        if remaining <= 0 or self.sequence >= 16:
            raise TimeoutError("Garage original cutoff or exchange count exhausted")
        credentials = json.loads(_private_file(self.credentials_file, 4096))
        if (set(credentials) != {"accessKeyId", "secretAccessKey"}
                or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_+/=-]{1,256}", value)
                       for value in credentials.values())):
            raise ValueError("Garage selected credential file differs")
        stem = self.directory / ("instrumentation-%02d" % self.sequence)
        self.sequence += 1
        response, headers = Path(str(stem) + ".body"), Path(str(stem) + ".headers")
        for output in (response, headers):
            _create(output, b"")
        target = self.origin + "/" + bucket + "/" + quote(key, safe="/")
        if version is not None:
            target += "?" + urlencode({"versionId": version})
        configuration = ('user = "' + credentials["accessKeyId"] + ":"
                         + credentials["secretAccessKey"] + '"\n'
                         + 'aws-sigv4 = "aws:amz:' + self.region + ':s3"\n')
        arguments = [self.curl, "--silent", "--show-error", "--config", "-",
                     "--max-time", str(min(20, remaining)), "--max-filesize", str(MAX_OBJECT),
                     "--dump-header", str(headers), "--output", str(response),
                     "--write-out", "%{http_code}"]
        if method == "HEAD":
            arguments.append("--head")
        else:
            arguments.extend(["--request", method])
        if if_match is not None:
            arguments.extend(["--header", "If-Match: " + if_match])
        if body is not None:
            request = Path(str(stem) + ".request")
            _create(request, body)
            arguments.extend(["--data-binary", "@" + str(request)])
        arguments.append(target)
        record = {"scope": "fixture_instrumentation", "method": method,
                  "keySha256": hashlib.sha256(key.encode()).hexdigest(),
                  "outcome": "unknown", "status": None, "exitCode": None}
        self.records.append(record)
        # A timeout remains unknown, with its files and original record retained.
        completed = subprocess.run(arguments, input=configuration.encode(), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=min(21, remaining), check=False)
        with response.open("rb") as source:
            raw = source.read(MAX_OBJECT + 1)
        with headers.open("rb") as source:
            header_bytes = source.read(MAX_REPLY + 1)
        record.update(exitCode=completed.returncode,
                      status=int(completed.stdout) if re.fullmatch(rb"[0-9]{3}", completed.stdout) else None,
                      bodySha256=hashlib.sha256(raw).hexdigest(), bodyBytes=len(raw),
                      headersSha256=hashlib.sha256(header_bytes).hexdigest(), headersBytes=len(header_bytes),
                      bodyFile=str(response), headersFile=str(headers),
                      stderrSha256=hashlib.sha256(completed.stderr).hexdigest())
        if completed.returncode != 0 or len(raw) > MAX_OBJECT or len(header_bytes) > MAX_REPLY:
            raise RuntimeError("Garage instrumentation transport is unknown or exceeds its bound")
        record["outcome"] = "received"
        fields = {}
        for line in header_bytes.splitlines():
            if line.startswith(b"HTTP/"):
                fields = {}
            elif b":" in line:
                name, value = line.split(b":", 1)
                lower = name.decode("ascii").lower()
                if lower in {"etag", "content-length", "x-amz-version-id"}:
                    if lower in fields:
                        raise ValueError("Garage selected response header duplicated")
                    fields[lower] = value.strip().decode("ascii")
        return {"status": record["status"], "headers": fields, "body": raw}


class GarageReplacement:
    """Replace one actual closed object once; never synthesize a refusal reply."""

    def __init__(self, transport, admission, placement_id, closed, run_digest):
        rows = [row for row in admission["placements"] if row["placementId"] == placement_id]
        if (len(rows) != 1 or not DIGEST.fullmatch(run_digest)
                or set(closed) != {"etag", "providerVersion"}
                or not re.fullmatch(r'"[A-Za-z0-9_-]{1,128}"', closed["etag"])
                or not 0 < int(admission["intent"]["byteSize"]) <= MAX_OBJECT):
            raise ValueError("Garage replacement needs one actual bounded closed source")
        placement = rows[0]
        physical = placement["physical"]
        if physical["kind"] != "external":
            raise ValueError("Garage replacement is not a Managed R2 fault adapter")
        write, read = physical["writeCohort"], physical["readCohort"]
        bucket = write["alias"]["spec"]["bucket"]
        if (bucket != read["alias"]["spec"]["bucket"]
                or not re.fullmatch(r"[a-z0-9-]{3,63}", bucket)
                or not DIGEST.fullmatch(admission["intent"]["expectedSha256"])
                or closed["providerVersion"] is not None and
                (not isinstance(closed["providerVersion"], str)
                 or not 0 < len(closed["providerVersion"]) <= 1024
                 or closed["providerVersion"] == "null")):
            raise ValueError("Garage original cohorts or incarnation differ")
        prefix = placement["stagingPrefix"]
        key = prefix + "/" + hashlib.sha256(admission["sessionId"].encode()).hexdigest() + "/" + placement_id + "/payload"
        self.transport, self.closed, self.key = transport, dict(closed), key
        self.bucket = bucket
        self.source_sha = admission["intent"]["expectedSha256"]
        self.source_bytes = int(admission["intent"]["byteSize"])
        self.run_digest, self.dispatched = run_digest, False

    def replace_once(self, marker):
        """Persist the one-shot marker before a real conditional PUT.

        The caller owns the selected GET pause and must always release it. This
        method itself supplies no held-GET, queue, provider-start or expiry proof.
        """
        if self.dispatched:
            raise ValueError("Garage replacement was already dispatched or became unknown")
        old = self.transport.exchange("GET", self.bucket, self.key,
                                      version=self.closed["providerVersion"], if_match=self.closed["etag"])
        if (old["status"] != 200 or len(old["body"]) != self.source_bytes
                or hashlib.sha256(old["body"]).hexdigest() != self.source_sha
                or old["headers"].get("etag") != self.closed["etag"]
                or old["headers"].get("x-amz-version-id") != self.closed["providerVersion"]):
            raise ValueError("actual Garage original source or incarnation differs")
        replacement = bytearray(old["body"])
        replacement[0] ^= 0xff
        _create(Path(marker), json.dumps({"version": 1, "runDigest": self.run_digest,
                "keySha256": hashlib.sha256(self.key.encode()).hexdigest(),
                "originalSha256": self.source_sha, "state": "dispatch_pending"}).encode())
        self.dispatched = True
        put = self.transport.exchange("PUT", self.bucket, self.key,
                                      if_match=self.closed["etag"], body=bytes(replacement))
        if put["status"] not in {200, 201, 204}:
            return {"state": "unavailable", "reason": "conditional_replacement_not_acknowledged",
                    "status": put["status"], "qualification": None}
        current = self.transport.exchange("GET", self.bucket, self.key)
        changed_sha = hashlib.sha256(replacement).hexdigest()
        if (current["status"] != 200 or current["body"] != bytes(replacement)
                or current["headers"].get("etag") in {None, self.closed["etag"]}):
            raise ValueError("acknowledged Garage replacement is not the selected actual source")
        old_read = self.transport.exchange("GET", self.bucket, self.key,
                                           version=self.closed["providerVersion"], if_match=self.closed["etag"])
        if old_read["status"] == 200:
            return {"state": "unavailable", "reason": "old_pinned_incarnation_remains_readable",
                    "qualification": None}
        if old_read["status"] not in {404, 412}:
            return {"state": "unknown", "reason": "old_incarnation_refusal_unknown",
                    "status": old_read["status"], "qualification": None}
        return {"state": "replacement_observed", "runDigest": self.run_digest,
                "keySha256": hashlib.sha256(self.key.encode()).hexdigest(),
                "oldSha256": self.source_sha, "newSha256": changed_sha,
                "oldEtagSha256": hashlib.sha256(self.closed["etag"].encode()).hexdigest(),
                "newEtagSha256": hashlib.sha256(current["headers"]["etag"].encode()).hexdigest(),
                "byteSize": self.source_bytes, "instrumentationOldReadStatus": old_read["status"],
                "productionConditionalRead": None, "qualification": None}
