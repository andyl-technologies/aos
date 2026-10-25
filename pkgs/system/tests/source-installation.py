"""Cross-checks actual built Parent and Source leaves against their one producer.

This integration validator reads build artifacts only. It creates no wire image,
resource policy, service authority or installed-fit proof. The existing shared
Source profile validator owns the service grammar.
"""

import hashlib
import importlib.util
import json
import os
import struct
from pathlib import Path


def fixed_text(raw):
    value, separator, padding = raw.partition(b"\0")
    if not separator or any(padding):
        raise ValueError("noncanonical Parent fixed string")
    return value.decode("ascii")


def validate():
    parent = Path(os.environ["parentImage"]) / "enclosure.bin"
    units = Path(os.environ["unitImage"])
    bootstrap = Path(os.environ["bootstrapImage"]) / "bootstrap.bin"
    raw = parent.read_bytes()
    if raw[:8] != b"AOSRPE06" or hashlib.sha256(raw[:-32]).digest() != raw[-32:]:
        raise ValueError("final Parent06 header or checksum mismatch")
    if raw[8:40] != hashlib.sha256(bootstrap.read_bytes()).digest():
        raise ValueError("Parent does not bind the actual selected bootstrap")
    count = struct.unpack_from(">H", raw, 452)[0]
    if not 1 <= count <= 18 or len(raw) != 3478 + 1506 * count:
        raise ValueError("Parent06 full geometry mismatch")
    dimensions = json.loads(os.environ["dimensionJson"])
    contract = json.loads(os.environ["contractJson"])
    if len(dimensions) != 22 or len(set(dimensions)) != 22:
        raise ValueError("actual dimension registry mismatch")
    ranges = ["sourceSignerReceiving", "sourceSignerSender", "controllerSuccessorSender",
              "ownershipReceiving", "ownershipSender", "cacheSignerReceiving", "cacheSignerSender", "mountReceiving", "mountSender",
              "networkReceiving", "networkSender", "hostBootPreparationReceiving",
              "hostBootPreparationSender", "method46ControllerInitialReceiving",
              "method46ControllerInitialSender", "method46StorageInitialReceiving",
              "method46StorageInitialSender"]
    expected = []
    for name in ranges:
        vector = contract[name]
        expected.extend([0] * 22 if vector is None else [vector[key] for key in dimensions])
    if tuple(expected) != struct.unpack_from(">374Q", raw, 454):
        raise ValueError("actual Parent range commitments differ from selected configuration")

    spec = importlib.util.spec_from_file_location("source_profile", os.environ["profileValidator"])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    profile = module.SourceProtectedProfileV1(os.environ["expectedSourceExec"])
    cache_enabled = os.environ["cacheEnabled"] == "yes"
    profiles = [profile]
    if cache_enabled:
        profiles.append(module.CacheProtectedProfileV1(os.environ["expectedCacheExec"]))
    names = []
    source_seen = False

    def leaf(encoded):
        path = fixed_text(encoded[:256])
        content = (units / path).read_bytes()
        if len(content) > 65536 or hashlib.sha256(content).digest() != encoded[256:288]:
            raise ValueError("actual unit leaf differs from Parent commitment")
        for profile in profiles:
            if path == profile.unit or path.startswith(profile.unit + ".d/"):
                profile.observe(path, content)
        return path

    for index in range(count):
        row = raw[3446 + 1506 * index:3446 + 1506 * (index + 1)]
        name = fixed_text(row[:64])
        names.append(name)
        if leaf(row[64:352]) != name:
            raise ValueError("Parent base leaf is not its exact member")
        drops = struct.unpack_from(">H", row, 352)[0]
        if drops > 4:
            raise ValueError("Parent drop-in count exceeds actual fixed profile")
        drop_names = [leaf(row[354 + 288 * n:642 + 288 * n]) for n in range(drops)]
        if drop_names != sorted(set(drop_names)) or any(not p.startswith(name + ".d/") for p in drop_names):
            raise ValueError("Parent drop-in association changed")
        if any(row[354 + 288 * drops:]):
            raise ValueError("Parent unused leaf slots are nonzero")
        source_seen |= name == module.SOURCE_UNIT
    if names != sorted(set(names)) or not source_seen:
        raise ValueError("actual fixed roster lacks its unique selected Source service")
    if (module.CACHE_UNIT in names) != cache_enabled:
        raise ValueError("actual Cache roster differs from the selected installation")
    for unit, receiving, sender in (
        ("aos-sandbox-controller-floor-initialize.service",
         "method46ControllerInitialReceiving", "method46ControllerInitialSender"),
        ("aos-sandbox-storage-floor-initialize.service",
         "method46StorageInitialReceiving", "method46StorageInitialSender"),
    ):
        selected = contract[receiving] is not None
        if (unit in names) != selected or (contract[sender] is not None) != selected:
            raise ValueError("actual manual initial-floor roster differs from its selected partition")
    for profile in profiles:
        profile.require_complete()

    # Inspect the real rendered socket and declared drop-ins in load order.
    # Source's service grammar stays in its existing shared validator above.
    def require_prelisten_socket(leaves, expected_socket):
        flags = {name: None for name in ["PassCredentials", "PassPIDFD", "PassSecurity", "PassSubjectBeforeListen"]}
        socket_leaves = leaves
        if not socket_leaves or socket_leaves[0] != expected_socket:
            raise ValueError("actual selected signer socket base is absent")
        for path in socket_leaves:
            section = None
            for line in (units / path).read_text().splitlines():
                line = line.strip()
                if line.startswith("["):
                    section = line
                elif section == "[Socket]" and "=" in line:
                    name, value = line.split("=", 1)
                    if name.strip() in flags:
                        flags[name.strip()] = value.strip().lower()
        if any(value not in ("yes", "true", "1") for value in flags.values()):
            raise ValueError("final socket does not enable all four options before listen")

    require_prelisten_socket(json.loads(os.environ["socketLeavesJson"]), "aos-sandbox-source-signerd.socket")
    if cache_enabled:
        require_prelisten_socket(json.loads(os.environ["cacheSocketLeavesJson"]), "aos-sandbox-cache-signerd.socket")
    if not (Path(os.environ["rootProfile"]) / "profile.json").is_file():
        raise ValueError("actual selected Root profile is absent")
    if not Path(os.environ["selectedPolicy"]).is_dir():
        raise ValueError("actual configured selected policy artifact is absent")


if __name__ == "__main__":
    validate()
