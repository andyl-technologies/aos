# SPDX-License-Identifier: MIT
"""Exercises a source-built Linux driver on the actual modern ARM MMIO device.

The functional board supplies no exact-state or CPU-timing admission. Its
finite event budget and guest markers distinguish a genuine completed driver
roundtrip from firmware startup or a device-only descriptor witness.
"""

import json
from pathlib import Path
import struct
import sys

import m5
from m5.objects import (
    ArmAtomicSimpleCPU, Root, SimpleMemory, SrcClockDomain, VirtIONet,
    VoltageDomain,
)

if len(sys.argv) != 6:
    raise RuntimeError("expected configs, kernel ELF, initramfs, bootloader, and tick budget")

configs, kernel, initrd, bootloader, ticks = sys.argv[1:]
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
            "net.ifnames=0 gem5_probe=network",
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
system.net = VirtIONet(queue_size=256, frame_capacity=16, maximum_frame_bytes=65536)
system.realview.vio[0].vio = system.net
system.realview.vio[0].modern = True
root = Root(full_system=True, system=system)
dtb = str(Path(m5.options.outdir) / "fixture.dtb")
system.generateDtb(dtb)
system.workload.dtb_filename = dtb
m5.instantiate()
assert system.net.setExecutionParent(17)

terminal = Path(m5.options.outdir) / "system.terminal"
expected_packet = bytes([255] * 6 + [2, 0, 0, 0, 0, 1, 0x88, 0xb5])
expected_packet += b"CRUCIBLE_GEM5_NATIVE_FRAME"[:25] + bytes(25)
assert len(expected_packet) == 64
next_input = 1
published = {}
completed = []
processed = 0
verified = False
cause = "exclusive native tick budget"
while True:
    result = m5.simulateUntilBoundary(exclusive_tick, 100000)
    processed += result.processedEvents
    metadata = list(system.net.pendingTxMetadata())
    if metadata:
        assert len(metadata) == 5
        identifier, tick, parent, ordinal, tie = metadata
        payload = bytes(system.net.pendingTxBytes())
        assert parent == 17 and ordinal > 0 and tie > 0
        assert identifier not in published and len(published) < 64
        assert list(system.net.pendingTxMetadata()) == metadata
        assert bytes(system.net.pendingTxBytes()) == payload
        assert system.net.stageRx(next_input, m5.curTick() + 1, 23, list(payload))
        published[identifier] = (next_input, payload, tick, ordinal, tie)
        assert not system.net.acknowledgeTx(identifier + 1)
        assert system.net.acknowledgeTx(identifier)
        next_input += 1

    retained = list(system.net.pendingRxMetadata())
    if retained and retained[3] == 1:
        metadata = list(system.net.pendingRxCompletionMetadata())
        assert len(metadata) >= 7 and len(metadata) % 7 == 0
        identifier, tick, ordinal, tie, execution, parent, count = metadata[:7]
        original = next(row for row in published.values() if row[0] == identifier)
        assert retained[0] == identifier and ordinal > original[3] and tie > 0
        assert execution == 17 and parent == 23 and count == len(original[1])
        completed.append((identifier, original[1], tick, ordinal, tie))
        assert system.net.retireRx(identifier)

    if terminal.exists():
        console = terminal.read_bytes()
        if b"GEM5_LINUX_PROBE_FAILED" in console:
            raise RuntimeError("actual ARM Linux device probe failed")
        if b"GEM5_LINUX_PROBE_COMPLETE" in console:
            assert b"GEM5_LINUX_INIT_READY" in console
            assert b"GEM5_NETWORK_TX_READY bytes=64" in console
            assert b"GEM5_NETWORK_RX_VERIFIED bytes=64" in console
            assert any(row[1] == expected_packet for row in completed)
            verified = True
            cause = "actual ARM Linux modern MMIO network roundtrip completed"
            break

    print(json.dumps({
        "schema": "crucible.gem5.linux-boot-progress.v1",
        "guestISA": "aarch64", "nativeTick": str(result.currentTick),
        "processedEvents": str(processed),
        "committedInstructions": str(system.cpu.totalInsts()),
    }, sort_keys=True, separators=(",", ":")), flush=True)
    if result.exitEvent is not None:
        cause = result.exitEvent.getCause()
        break
    if not result.hasNextEvent or result.nextTick >= exclusive_tick:
        break

if not verified:
    raise RuntimeError(f"ARM Linux driver roundtrip did not complete: {cause}")
print(json.dumps({
    "schema": "crucible.gem5.aarch64-linux-network-mechanism.v1",
    "nativeTick": str(m5.curTick()), "processedEvents": str(processed),
    "linuxGuestRoundtripVerified": True, "actualRoundtripBytes": 64,
    "nativeOutputBirthVerified": True, "nativeInputCompletionVerified": True,
    "fixtureClock": "100MHz", "functionalInstructionWidth": 16,
    "cpuTimingQualified": False, "deviceParityQualified": False,
    "completeStateQualified": False, "coordinatorAdmissionQualified": False,
}, sort_keys=True, separators=(",", ":")))
