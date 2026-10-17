# SPDX-License-Identifier: MIT
"""Exercises actual Linux 9p mount/create/read/write/flush with finite custody.

The fixture owns a bounded in-memory tree and never accesses a host filesystem.
Native original messages and sealed future replies are independently checked
against actual Linux guest markers; no full-system exact authority is claimed.
"""

import importlib.util
import json
from pathlib import Path
import struct
import sys

import m5
from m5.objects import (
    ArmAtomicSimpleCPU, Root, SimpleMemory, SrcClockDomain, VirtIOHostRequest,
    VoltageDomain,
)

if len(sys.argv) != 7:
    raise RuntimeError("expected configs, kernel ELF, initramfs, bootloader, tick budget, and finite 9p fixture")

configs, kernel, initrd, bootloader, ticks, fixture_path = sys.argv[1:]
spec = importlib.util.spec_from_file_location("finite_ninep_fixture", fixture_path)
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)
fixture = fixture_module.FiniteNinepFixture()
sys.path.insert(0, configs)
from common.Benchmarks import SysConfig
from common.FSConfig import makeArmSystem

exclusive_tick = int(ticks)
if not 0 < exclusive_tick < (1 << 64):
    raise RuntimeError("fixture requires a bounded positive native tick budget")
if not 0 < Path(initrd).stat().st_size <= 32 * 1024 * 1024:
    raise RuntimeError("initramfs exceeds its bounded ARM loader region")


def validate_loader_regions(kernel_path, initrd_path):
    """Checks the native KernelWorkload relocation against board-owned regions."""
    with Path(kernel_path).open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise RuntimeError("fixture requires a little-endian ELF64 kernel")
        if struct.unpack_from("<H", header, 18)[0] != 183:
            raise RuntimeError("fixture requires an AArch64 kernel")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        if size != 56 or not 0 < count <= 128:
            raise RuntimeError("kernel ELF program headers exceed fixture bounds")
        stream.seek(offset)
        table = stream.read(size * count)
        if len(table) != size * count:
            raise RuntimeError("kernel ELF program headers are truncated")

    segments = []
    for index in range(count):
        values = struct.unpack_from("<IIQQQQQQ", table, index * size)
        if values[0] == 1 and values[6]:
            if values[6] >= 1 << 64 or values[4] > (1 << 64) - values[6]:
                raise RuntimeError("kernel ELF physical extent wraps")
            segments.append((values[4], values[6]))
    if not segments:
        raise RuntimeError("kernel has no bounded loadable extent")
    start = min(address for address, _ in segments)
    end = max(address + extent - 1 for address, extent in segments)
    # This is the native loader's smallest mask covering the image span.
    mask = (1 << max(1, (end - start).bit_length())) - 1
    reserved = [(0x88000000, 0x200000), (0x88200000, Path(initrd_path).stat().st_size)]
    for address, extent in segments:
        physical = (address & mask) + 0x80000000
        if physical < 0x80000000 or physical + extent > 0x90000000:
            raise RuntimeError("kernel relocated extent exceeds fixture RAM")
        for base, length in reserved:
            if physical < base + length and base < physical + extent:
                raise RuntimeError("kernel relocated extent overlaps DTB or initramfs")


validate_loader_regions(kernel, initrd)
system = makeArmSystem(
    "atomic", "VExpress_GEM5_V2", num_cpus=1,
    mdesc=SysConfig(mem="256MiB", disks=[]), bootloader=[bootloader],
    cmdline="console=ttyAMA0 earlycon=pl011,0x1c090000 rdinit=/init panic=1 "
            "lpj=1000000 init_on_alloc=0 init_on_free=0 nokaslr "
            "net.ifnames=0 gem5_probe=9p",
)
system.voltage_domain = VoltageDomain()
system.clk_domain = SrcClockDomain(clock="100MHz", voltage_domain=system.voltage_domain)
system.workload.object_file = kernel
system.workload.initrd_filename = initrd
system.cpu = ArmAtomicSimpleCPU(cpu_id=0, width=16)
system.cpu.createThreads()
system.cpu.createInterruptController()
system.cpu.connectBus(system.membus)
system.memory = SimpleMemory(range=system.mem_ranges[0])
system.memory.port = system.membus.mem_side_ports

# Retain the board-owned transport, port connections, IRQ and DT generator.
# Replacing only its device and version keeps the published board geometry.
system.device = VirtIOHostRequest(
    kind="9p", queue_size=256, request_capacity=16,
    maximum_payload_bytes=65536, capacity_sectors=2048,
)
system.realview.vio[0].vio = system.device
system.realview.vio[0].modern = True
root = Root(full_system=True, system=system)
dtb = str(Path(m5.options.outdir) / "fixture.dtb")
system.generateDtb(dtb)
system.workload.dtb_filename = dtb
m5.instantiate()
assert system.device.setExecutionParent(17)

terminal = Path(m5.options.outdir) / "system.terminal"

requests = {}
completed = {}

processed = 0
verified = False
while True:
    result = m5.simulateUntilBoundary(exclusive_tick, 100000)
    processed += result.processedEvents

    while True:
        metadata = list(system.device.pendingRequestMetadata())
        if not metadata:
            break
        if len(metadata) != 9:
            raise RuntimeError("native 9p request has unknown metadata geometry")
        identifier, tick, parent, opcode, sector, tag, count, ordinal, tie = metadata
        original = bytes(system.device.pendingRequestBytes())
        assert parent == 17 and ordinal > 0 and tie > 0 and 0 <= tag <= 65535
        assert identifier not in requests and len(requests) < 1024
        assert metadata == list(system.device.pendingRequestMetadata())
        assert original == bytes(system.device.pendingRequestBytes())
        assert sector == 0 and len(original) >= 7
        assert original[4] == opcode and struct.unpack_from("<H", original, 5)[0] == tag
        reply = fixture.reply(original)
        assert len(reply) <= count
        sealed_tick = m5.curTick() + 1
        assert not system.device.stageReply(identifier + 1024, sealed_tick, 23, 0, list(reply))
        assert system.device.stageReply(identifier, sealed_tick, 23, 0, list(reply))
        assert system.device.stageReply(identifier, sealed_tick, 23, 0, list(reply))
        assert not system.device.stageReply(identifier, sealed_tick, 24, 0, list(reply))
        requests[identifier] = (metadata, original, reply, sealed_tick)
        assert not system.device.acknowledgeRequest(identifier + 1)
        assert system.device.acknowledgeRequest(identifier)

    receipt = list(system.device.pendingCompletionMetadata())
    if receipt:
        assert len(receipt) % 9 == 0
        for offset in range(0, len(receipt), 9):
            identifier, tick, ordinal, tie, status, count, execution, parent, incarnation = receipt[offset:offset + 9]
            metadata, original, reply, sealed_tick = requests[identifier]
            assert tick == sealed_tick and ordinal > metadata[7] and tie > 0
            assert status == 0 and count == len(reply)
            assert execution == 17 and parent == 23 and incarnation > 0
            assert identifier not in completed
            completed[identifier] = receipt[offset:offset + 9]
            assert system.device.retireCompleted(identifier)

    if terminal.exists():
        console = terminal.read_bytes()
        if b"GEM5_LINUX_PROBE_FAILED" in console:
            raise RuntimeError("actual Linux 9p probe failed")
        if b"GEM5_LINUX_PROBE_COMPLETE" in console:
            assert b"GEM5_LINUX_INIT_READY" in console
            assert b"GEM5_9P_READ_WRITE_FLUSH_VERIFIED" in console
            assert all(fixture.operations.get(opcode, 0) for opcode in (100, 104, 110, 24, 14, 116, 118, 50))
            assert requests.keys() == completed.keys()
            assert bytes(fixture.data) == b"crucible native 9p ownership\n\0"
            assert fixture.flushed_bytes == bytes(fixture.data)
            verified = True
            break
    if processed % 2000000 == 0:
        print(json.dumps({
            "schema": "crucible.gem5.linux-ninep-progress.v1",
            "nativeTick": str(m5.curTick()), "processedEvents": str(processed),
            "originalRequests": len(requests), "completedReplies": len(completed),
        }, sort_keys=True, separators=(",", ":")), flush=True)
    if result.exitEvent is not None:
        raise RuntimeError(f"native guest exited before 9p completion: {result.exitEvent.getCause()}")
    if not result.hasNextEvent or result.nextTick >= exclusive_tick:
        break

if not verified:
    raise RuntimeError("actual Linux 9p roundtrip did not complete in its finite budget")
print(json.dumps({
    "schema": "crucible.gem5.aarch64-linux-ninep-mechanism.v1",
    "nativeTick": str(m5.curTick()), "processedEvents": str(processed),
    "originalRequests": len(requests), "completedReplies": len(completed),
    "operations": {str(key): value for key, value in fixture.operations.items()},
    "actualRoundtripBytes": len(fixture.data),
    "linuxGuestRoundtripVerified": True,
    "nativeOriginalRequestBirthVerified": True,
    "nativeReplyCompletionVerified": True,
    "fixtureClock": "100MHz", "functionalInstructionWidth": 16,
    "cpuTimingQualified": False, "deviceParityQualified": False,
    "completeStateQualified": False, "coordinatorAdmissionQualified": False,
}, sort_keys=True, separators=(",", ":")))
