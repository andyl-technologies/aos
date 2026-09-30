"""Observes native filesystem claims and actual nftables state in the guest.

The selected owner comes from protected backend receipts. Kernel and file
observations independently check those claims; desired graphs are never input.
"""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def receipts(root):
    """Reads bounded protected receipts without following filesystem links."""
    root = Path(root)
    if not root.exists():
        return []
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("unprotected native receipt directory")
    paths = sorted(root.glob("*.json"))
    if len(paths) > 4096:
        raise ValueError("receipt inventory exceeds bound")
    result = []
    for path in paths:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError("unprotected native receipt")
            data = source.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            raise ValueError("receipt exceeds bound")
        record = json.loads(data)
        if not isinstance(record.get("id"), str) or not record["id"]:
            raise ValueError("receipt has no owner")
        result.append(record)
    return result


def resource(path, records, configuration=False, foreign=False, identity=False):
    """Checks actual inode, metadata and content against actual backend claims."""
    path = Path(path)
    claims = [record for record in records if str(path) in (record.get("path"), record.get("previous_path"))]
    owners = sorted({claim["id"] for claim in claims})
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {"exists": False, "owners": owners}
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        result = {"exists": True, "owners": owners, "mode": format(mode, "04o"), "uid": metadata.st_uid, "gid": metadata.st_gid}
        if stat.S_ISREG(metadata.st_mode):
            chunks = []
            remaining = MAX_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > MAX_BYTES:
                raise ValueError("resource exceeds observation bound")
            result.update(kind="file", digest="sha256:" + hashlib.sha256(data).hexdigest())
        elif stat.S_ISDIR(metadata.st_mode):
            entries = sorted(os.listdir(descriptor))
            if len(entries) > 4096:
                raise ValueError("directory inventory exceeds bound")
            result.update(kind="directory", entries=entries)
        else:
            raise ValueError("unsupported resource kind")
    finally:
        os.close(descriptor)
    if foreign or identity:
        # Custody checks include the actual inode even when a configuration
        # receipt authorizes bytes only. Equal replacement bytes are distinct.
        result.update(device=metadata.st_dev, inode=metadata.st_ino)
    if foreign:
        return result
    if configuration:
        result["claimMatches"] = len(claims) == 1 and claims[0].get("digest") == result.get("digest", "").removeprefix("sha256:")
    else:
        result["claimMatches"] = len(claims) == 1 and all((
            claims[0].get("device") == metadata.st_dev,
            claims[0].get("inode") == metadata.st_ino,
            claims[0].get("mode") == mode,
            claims[0].get("uid") in (None, metadata.st_uid),
            claims[0].get("gid") in (None, metadata.st_gid),
            claims[0].get("digest") in (None, result.get("digest")),
        ))
    return result


def nft_table(nft, table):
    """Reads a bounded actual kernel table; only absence is accepted as missing."""
    process = subprocess.run([nft, "-j", "list", "table", "inet", table], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if len(process.stdout) > 8 * 1024 * 1024 or len(process.stderr) > 64 * 1024:
        raise ValueError("nft observation exceeds bound")
    if process.returncode:
        if b"No such file or directory" in process.stderr:
            return None
        raise ValueError("nft observation failed: " + process.stderr.decode(errors="replace"))
    return json.loads(process.stdout)


def ruleset_projection(value, records, identity=False):
    """Checks kernel policy and ports against the handler's exact observation hash."""
    if len(records) > 1:
        raise ValueError("ruleset backend has multiple ownership receipts")
    owners = sorted(record["id"] for record in records)
    if value is None:
        return {"exists": False, "owners": owners}
    ports = {"tcp": set(), "udp": set()}
    policies = {}
    for entry in value["nftables"]:
        chain = entry.get("chain")
        if chain is not None and "policy" in chain:
            policies[chain["name"]] = chain["policy"]
        rule = entry.get("rule")
        if rule is None or not any("accept" in expr for expr in rule.get("expr", [])):
            continue
        for expr in rule["expr"]:
            match = expr.get("match", {})
            payload = match.get("left", {}).get("payload", {})
            if payload.get("field") != "dport" or payload.get("protocol") not in ports:
                continue
            right = match.get("right")
            values = right.get("set", []) if isinstance(right, dict) else [right]
            if any(type(port) is not int or not 1 <= port <= 65535 for port in values):
                raise ValueError("unexpected nft port expression")
            ports[payload["protocol"]].update(values)
    digest = "sha256:" + hashlib.sha256(b"aos.network.ruleset-observation/v1\0" + canonical(value)).hexdigest()
    result = {"exists": True, "owners": owners, "policies": policies, "tcp": sorted(ports["tcp"]), "udp": sorted(ports["udp"]), "claimMatches": len(records) == 1 and records[0].get("observed_digest") == digest}
    if identity:
        # Ports and policies alone omit foreign rules, handles and expressions.
        # Mutation-refusal checks compare the complete kernel observation.
        result["kernelDigest"] = digest
    return result




def dependency_claim(contents):
    """Decodes the exact bounded claim bytes written by the real marker backend."""
    if len(contents) > 16384:
        raise ValueError("dependency marker exceeds its bound")
    claim = json.loads(contents)
    if not isinstance(claim, dict) or set(claim) != {"effect", "revision"} or any(
        not isinstance(value, str) or not value or len(value.encode()) > 1024
        for value in claim.values()
    ):
        raise ValueError("dependency marker has no exact native claim")
    return claim


def dependency_marker(path):
    """Reads a real protected marker independently of its requested graph."""
    path = Path(path)
    root = Path("/var/lib/aos/native-dependency-barrier")
    if path.parent != root or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", path.name) is None:
        raise ValueError("dependency marker escapes its fixture root")
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
        raise ValueError("dependency marker directory is not protected")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {"exists": False, "owners": []}
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ValueError("dependency marker is not protected")
        contents = source.read(16385)
    claim = dependency_claim(contents)
    return {
        "exists": True, "owners": [claim["effect"]], "revision": claim["revision"],
        "device": metadata.st_dev, "inode": metadata.st_ino,
        "digest": "sha256:" + hashlib.sha256(contents).hexdigest(),
        "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
    }


def observe(request):
    """Collects selected ownership and independent foreign substrate facts."""
    if request["domain"] == "dependency":
        return {"selected": dependency_marker(request["selected"]), "foreign": observe(request["witness"])["foreign"]}
    if request["domain"] == "firewall":
        records = receipts("/var/lib/aos/network-ruleset")
        return {"selected": ruleset_projection(nft_table(request["nft"], "aos_filter"), records, identity=request.get("identity", False)), "foreign": nft_table(request["nft"], request["foreign"])}
    configuration = request["domain"] == "configuration"
    root = "/var/lib/aos/native-service-effects" if configuration else "/var/lib/aos/native-filesystem"
    records = receipts(root)
    return {"selected": resource(request["selected"], records, configuration, identity=request.get("identity", False)), "foreign": resource(request["foreign"], records, foreign=True)}


if __name__ == "__main__":
    print(json.dumps(observe(json.loads(sys.argv[1])), sort_keys=True))
