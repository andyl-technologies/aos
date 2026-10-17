"""Install separate strict TLS observation proxies for the fresh Managed pair.

Templates reuse the ordinary fixture's exact body/control formats. The initial
Native/MF listeners must already be selected at 4646/4645 before observations;
the public localhost origins stay at 4644/4643. No External routing is changed.
"""

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat


def managed_proxy_template_bytes(reference):
    """Read a held hashed public template, without relaxing private file custody."""
    if (not isinstance(reference, dict) or set(reference) != {"path", "sha256"}
            or not isinstance(reference["path"], str) or not Path(reference["path"]).is_absolute()
            or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])):
        raise ValueError("Managed proxy template reference differs")
    descriptor = os.open(reference["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        first = os.fstat(source.fileno())
        if (not stat.S_ISREG(first.st_mode) or first.st_uid not in {0, os.geteuid()}
                or first.st_mode & 0o022 or first.st_size > 64 * 1024):
            raise ValueError("Managed public template custody or bound differs")
        body = source.read(64 * 1024 + 1)
        last = os.fstat(source.fileno())
    if (len(body) != first.st_size or hashlib.sha256(body).hexdigest() != reference["sha256"]
            or any(getattr(first, field) != getattr(last, field)
                for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))):
        raise ValueError("Managed proxy template changed from the selected original")
    return body


def install_managed_storage_boundaries(native, worker, tools, run, worker_address, native_address):
    """Prepare confined per-run proxies; the pinned owner launches them afterwards."""
    if not re.fullmatch(r"[0-9a-f]{32}", run):
        raise ValueError("Managed capture run identity differs")
    address = ipaddress.ip_address(worker_address)
    if address.version != 4 or not address.is_private or address.is_loopback:
        raise ValueError("Managed actual Worker address differs")
    native_ip = ipaddress.ip_address(native_address)
    if (native_ip.version != 4 or not native_ip.is_private or native_ip.is_loopback
            or native_ip == address):
        raise ValueError("Managed actual Native address differs")
    roots = {"nativeInbound": "/var/lib/hybrid-managed-native/" + run + "/inbound",
        "nativeOutbound": "/var/lib/hybrid-managed-native/" + run + "/outbound",
        "workerBoundary": "/var/lib/hybrid-managed-worker/" + run + "/boundary",
        "workerNativeOutbound": "/var/lib/hybrid-managed-worker/" + run + "/native-outbound"}
    configurations = {}
    for role in ("native", "worker"):
        template = tools["managed" + role.title() + "ObservationProxyTemplate"]
        selected = managed_proxy_template_bytes(template).decode()
        if "@MANAGED_RUN@" not in selected:
            raise ValueError("Managed proxy template lacks its separate selected roots")
        selected = selected.replace("@MANAGED_RUN@", run)
        selected = selected.replace("@MANAGED_WORKER_ADDRESS@", str(address))
        selected = selected.replace("@MANAGED_NATIVE_ADDRESS@", str(native_ip))
        if "@MANAGED_" in selected:
            raise ValueError("Managed proxy template remains unresolved")
        target = "/var/lib/hybrid-managed-proxy-config/" + run + "/" + role + ".conf"
        machine = native if role == "native" else worker
        install_direct_guest_file(machine, tools["python"], target, selected.encode())
        configurations[role] = target
    native_receipt = start_direct_boundary_proxy(native, tools, roots["nativeInbound"],
        configurations["native"], [roots["nativeOutbound"]], prepare_only=True)
    worker_receipt = start_direct_boundary_proxy(worker, tools, roots["workerBoundary"],
        configurations["worker"], [roots["workerNativeOutbound"]], prepare_only=True)
    result = {"version": 1, "run": run, "roots": roots, "configurations": configurations,
        "workerAddress": str(address), "nativeAddress": str(native_ip),
        "nativeProxy": native_receipt, "workerProxy": worker_receipt,
        "nativePublicOrigin": "https://localhost:4644", "workerPublicOrigin": "https://localhost:4643",
        "nativeInternalListener": "127.0.0.1:4646", "workerInternalListener": "127.0.0.1:4645",
        "scope": "actual validated separate Managed configurations only; caller launches and observes processes, no authority/provider/Native bulk conclusion"}
    retain_direct_flow("managed-" + run + "-storage-boundary-installation.json", result)
    return result
