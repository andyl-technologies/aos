# SPDX-License-Identifier: MIT
"""Compares actual stopped native thread contexts with image bytes after exit."""

import ctypes
import importlib.util
import json
import mmap
import os
from pathlib import Path
import subprocess
import sys


def native_capture():
    library = ctypes.CDLL(None)
    assert library.dmtcp_crucible_checkpoint_thread_count() == -1
    assert library.dmtcp_crucible_checkpoint_fd_count() == -1
    assert library.dmtcp_crucible_checkpoint_map_count() == -1
    assert library.dmtcp_crucible_checkpoint_file_map_count() == -1
    guest_asset = Path("native-readonly-guest.elf").resolve()
    guest_asset.write_bytes(b"mapped-owned-ELF".ljust(8192, b"!"))
    guest_file = guest_asset.open("r+b")
    guest_mapping = mmap.mmap(guest_file.fileno(), 8192, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
    assert guest_mapping[:16].startswith(b"mapped-owned-ELF")
    library.dmtcp_checkpoint.restype = ctypes.c_int
    assert library.dmtcp_checkpoint() == 1
    count = library.dmtcp_crucible_checkpoint_thread_count()
    assert count == 2
    getter = library.dmtcp_crucible_checkpoint_thread
    getter.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint64),
                       ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_int),
                       ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_size_t]
    contexts = []
    for index in range(count):
        address, tid = ctypes.c_uint64(), ctypes.c_uint32()
        state, role = ctypes.c_int(), ctypes.c_int()
        buffer = ctypes.create_string_buffer(65536)
        size = getter(index, ctypes.byref(address), ctypes.byref(tid),
                      ctypes.byref(state), ctypes.byref(role), buffer, len(buffer))
        assert 0 < size <= len(buffer)
        contexts.append({"address": str(address.value), "real_tid": str(tid.value),
                         "state": state.value, "role": role.value,
                         "bytes_hex": buffer.raw[:size].hex()})
    assert getter(-1, None, None, None, None, None, 0) == -1
    shared_start, shared_end = ctypes.c_uint64(), ctypes.c_uint64()
    assert library.dmtcp_crucible_operational_shared_region(
        ctypes.byref(shared_start), ctypes.byref(shared_end)
    ) == 0
    assert shared_start.value < shared_end.value
    fd_getter = library.dmtcp_crucible_checkpoint_fd
    fd_getter.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint64),
                         ctypes.c_void_p, ctypes.c_size_t]
    descriptor_count = library.dmtcp_crucible_checkpoint_fd_count()
    assert 0 < descriptor_count <= 1024
    descriptors = []
    for index in range(descriptor_count):
        address = ctypes.c_uint64()
        buffer = ctypes.create_string_buffer(65536)
        size = fd_getter(index, ctypes.byref(address), buffer, len(buffer))
        assert size == 4160
        descriptors.append({"address": str(address.value),
                            "bytes_hex": buffer.raw[:size].hex()})
    assert fd_getter(descriptor_count, None, None, 0) == -1
    map_getter = library.dmtcp_crucible_checkpoint_map
    map_getter.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint64),
                          ctypes.c_void_p, ctypes.c_size_t]
    mapping_count = library.dmtcp_crucible_checkpoint_map_count()
    assert 0 < mapping_count <= 8192
    mappings = []
    for index in range(mapping_count):
        address = ctypes.c_uint64()
        buffer = ctypes.create_string_buffer(65536)
        size = map_getter(index, ctypes.byref(address), buffer, len(buffer))
        assert size == 1112
        mappings.append({"address": str(address.value),
                         "bytes_hex": buffer.raw[:size].hex()})
    assert map_getter(mapping_count, None, None, 0) == -1
    file_map_getter = library.dmtcp_crucible_checkpoint_file_map
    file_map_getter.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint64),
                               ctypes.c_void_p, ctypes.c_size_t]
    file_map_count = library.dmtcp_crucible_checkpoint_file_map_count()
    assert file_map_count == 1
    file_maps = []
    for index in range(file_map_count):
        address = ctypes.c_uint64()
        buffer = ctypes.create_string_buffer(5224)
        size = file_map_getter(index, ctypes.byref(address), buffer, len(buffer))
        assert size == 5224
        file_maps.append({"address": str(address.value), "bytes_hex": buffer.raw.hex()})
    assert file_map_getter(file_map_count, None, None, 0) == -1
    assert file_map_getter(0, None, None, 0) == -1
    print(json.dumps({"contexts": contexts, "descriptors": descriptors,
                      "mappings": mappings, "file_maps": file_maps,
                      "guest_asset": str(guest_asset)}), flush=True)
    # The parent inspects the kernel task roster while this source is parked;
    # the synchronization occurs strictly after the image has been written.
    assert sys.stdin.readline() == "exit\n"


def inspect(dmtcp, helper):
    root = Path("actual-context-capture").resolve()
    root.mkdir()
    (root / "images").mkdir()
    (root / "tmp").mkdir()
    child = subprocess.Popen([
        f"{dmtcp}/bin/dmtcp_launch", "--new-coordinator", "--coord-port", "0",
        "--interval", "0", "--no-gzip", "--ckpt-signal", "40",
        "--ckptdir", str(root / "images"), "--tmpdir", str(root / "tmp"),
        sys.executable, "-B", str(Path(__file__).resolve()), "native-capture",
    ], cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = child.stdout.readline()
    evidence = json.loads(output)
    kernel_tasks = sorted(int(name) for name in os.listdir(f"/proc/{child.pid}/task"))
    assert kernel_tasks == sorted(int(item["real_tid"]) for item in evidence["contexts"])
    remaining, errors = child.communicate(input=b"exit\n", timeout=60)
    assert not remaining
    assert child.returncode == 0, errors.decode()
    assert child.poll() == 0  # Inspection no longer depends on a living source.
    evidence = json.loads(output)
    contexts = evidence["contexts"]
    images = list((root / "images").glob("*.dmtcp"))
    assert len(images) == 1
    spec = importlib.util.spec_from_file_location("image_inventory", helper)
    inventory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventory)
    parsed = inventory.parse_image(images[0])
    assert sorted((context["role"], context["state"]) for context in contexts) == [(0, 3), (1, 4)]
    assert len({context["real_tid"] for context in contexts}) == 2
    for context in contexts:
        expected = bytes.fromhex(context["bytes_hex"])
        saved = inventory.captured_bytes(images[0], parsed["spans"],
                                        int(context["address"]), len(expected))
        assert expected == saved
        changed = bytearray(expected)
        changed[0] ^= 1
        assert bytes(changed) != saved
    for descriptor in evidence["descriptors"]:
        expected = bytes.fromhex(descriptor["bytes_hex"])
        saved = inventory.captured_bytes(images[0], parsed["spans"],
                                        int(descriptor["address"]), len(expected))
        assert expected == saved
    mappings = inventory.saved_kernel_maps(images[0], parsed["spans"], evidence["mappings"])
    assert len(mappings) > len(parsed["mappings"])
    captured = {(item["start"], item["end"]) for item in parsed["mappings"]}
    original = {(item["start"], item["end"]) for item in mappings}
    assert captured <= original
    altered = evidence["mappings"][0].copy()
    body = bytearray.fromhex(altered["bytes_hex"])
    body[0] ^= 1
    altered["bytes_hex"] = body.hex()
    try:
        inventory.saved_kernel_maps(images[0], parsed["spans"], [altered])
    except ValueError:
        pass
    else:
        raise AssertionError("altered native mapping record admitted")
    guest_asset = evidence["guest_asset"]
    digest, size = inventory.digest_file(guest_asset)
    assets = {guest_asset: {"sha256": digest, "bytes": str(size)}}
    supplementary = str(images[0]).removesuffix(".dmtcp") + "_files"
    receipts = inventory.verify_file_map_receipts(
        images[0], parsed["spans"], evidence["file_maps"], mappings,
        supplementary, guest_asset, assets, str(root))
    assert len(receipts) == 1
    assert receipts[0]["original_map"]["permissions"] == "r--s"
    changed = evidence["file_maps"][0].copy()
    payload = bytearray.fromhex(changed["bytes_hex"])
    payload[5208] = 0
    changed["bytes_hex"] = payload.hex()
    try:
        inventory.verify_file_map_receipts(
            images[0], parsed["spans"], [changed], mappings,
            supplementary, guest_asset, assets, str(root))
    except ValueError:
        pass
    else:
        raise AssertionError("altered native file mapping receipt admitted")
    print("actual native thread/descriptor/map/file-transformation image equality passed after source exit")


if sys.argv[1:] == ["native-capture"]:
    native_capture()
else:
    inspect(*sys.argv[1:])
