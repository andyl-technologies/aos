# ARM Linux full-system prerequisites and functional checks

The ARM fixture builds its kernel, PID1, initramfs and firmware from source on
the current x86-64 Linux machine. These artifacts enable actual driver checks;
source compilation alone does not establish device parity, CPU timing fidelity
or exact-state admission.

## Source and toolchain closure

`llvm-gem5` retains AOS LLVM 22's usual X86, AArch64, BPF and WebAssembly targets
and adds ARM32. The ordinary arm64 kernel's COMPAT vDSO requires that target.
No kernel feature is removed to avoid building it. All native kernel tools,
including the host compiler, binutils, OpenSSL, elfutils, Python and depmod,
come from source-built AOS packages.

`gem5-aarch64-linux` uses the central Linux 7.2.3 source pin and ordinary arm64
defconfig, building its Image, vmlinux, headers and complete configured module
tree. It makes the VExpress, GIC, timer, PL011, initramfs and modern VirtIO
network/block/9p paths built in. Its `source` output retains the exact upstream
archive, both applied source patches, build recipe and resolved configuration,
toolchain identities, original notices and binary commitments. The binary
output co-retains that source through `share/corresponding-source`.

The two kernel source changes preserve their original GPL notices:

- The existing AOS gawk argument patch supports the source-built host tool.
- The mksysmap patch excludes LLD's synthetic, address-derived Cortex-A53
  erratum-veneer symbol names from kallsyms, alongside the existing synthetic
  LLD thunk exclusions. The actual CPU-erratum veneer code and kernel feature
  remain present. Without this exclusion the actual final-link symbol set
  oscillated, shifting subsequent data symbols and failing Linux's kallsyms
  consistency check.

`gem5-aarch64-linux-device-fixture` builds a static freestanding PID1 using the
target kernel's sanitized UAPI, with no target or host libc. The small common
socket ABI header supplies `sockaddr`; compile-time assertions verify the
actual AArch64 `sockaddr` and `ifreq` extents. PID1 mounts proc/sysfs/devtmpfs,
reports readiness, and can exercise network, block and 9p roundtrips. The
initramfs builder writes deterministic newc records.

`gem5-aarch64-bootloader` compiles all four original AArch64 board bootloaders
from the pinned gem5 assembly using AOS Clang and LLD. The recipe makes LLD's
image base explicit while preserving the upstream entry address 0x10 and
original GICv2/GICv3 startup code. Each ELF is checked for AArch64 identity,
static loading, bounded segments and an executable entry. The original
BSD notices remain with the installed assembly and makefile.

## Actual native Linux scope

The functional network fixture uses VExpress_GEM5_V2, its GICv3 firmware,
256 MiB RAM and the board-owned modern VirtIO MMIO transport. The actual
native DT generator supplies the device tree. Before native loading, the
fixture checks kernel relocation against RAM and the reserved DTB/initramfs
regions. The model uses AtomicSimpleCPU, width 16 and 100 MHz to bound fixture
overhead; it makes no timing-fidelity claim.

The initial real Linux run reached serial, GIC, timer, network protocol and
driver initialization. At guest timestamp 0.191313 s, it raised an undefined
instruction in `crc32_be_arm64_4way`: opcode `0x0ee3e000`, decoded by AOS LLVM
as `pmull v0.1q, v0.1d, v3.1d`. The pinned simulator advertised FEAT_PMULL in
its realized release while its AdvSIMD decoder implemented only the byte
variant. This is a native ISA gap, not a successful PID1 or device witness.

The additive PMULL patch accepts the architectural 64-bit lower/upper forms,
guards them with the actual FEAT_PMULL extension, preserves byte forms and
rejects the reserved element sizes. It uses the existing widening-vector
executor for the full 128-bit polynomial result. Arm defines these operations
as multiplication of binary polynomials; their 64-bit variants belong to the
cryptographic extension. See the primary
[Arm instruction-set overview](https://armkeil.blob.core.windows.net/developer/Files/pdf/graphics-and-multimedia/ARMv8_InstructionSetOverview.pdf)
and [Arm cryptographic extension manual](https://documentation-service.arm.com/static/5e7e1430b471823cb9de57cf).

The separate guest regression executes all 4,096 basis pairs, dense and
deterministic additional vectors, both source halves, byte variants and
destination/source aliases. Its oracle multiplies independent coefficient
sets over GF(2). An instruction test cannot substitute for the mandatory
Linux guest readiness and exact 64-byte driver roundtrip markers.

The corrected native ISA completed the source-built Linux network check. The
installed check output is
`/nix/store/z468ad3889sprnabajklyapss4dkmpif-gem5-aarch64-linux-network-check-1`.
The guest executed `/init`, reported network transmit/read verification and
completed the probe. The fixture independently checked the retained native
64-byte publication, its original event birth and acknowledgment, and the
sealed receive input's native completion. It stopped at 416,133,330,000 ps
after 13,000,000 native events. The corresponding-source-retained kernel,
freestanding PID1, firmware and patched native emulator were all built locally.
This establishes a functional modern-MMIO network roundtrip.

The separate `gem5-aarch64-linux-block-check` output
`/nix/store/kk3l9mzbrl70pv14daaqd9iqgh1i2kp7-gem5-aarch64-linux-block-check-1`
also passed the actual Linux driver. Its fixed 1 MiB in-memory disk received
five original native requests: three reads, one write and one flush. Every
sealed reply completed at its scheduled future native tick with the original
request identity and birth/completion ordinals. The guest verified the exact
512-byte sector-one pattern after fsync and a fresh O_DIRECT read. Completion
occurred at 870,799,820,000 ps after 13,300,000 native events. The fixture uses
no host disk or file.

The `gem5-aarch64-linux-ninep-check` output
`/nix/store/2yiiw60w5kl923sjnxlnhi21iz29j9mz-gem5-aarch64-linux-ninep-check-1`
passed a real 9p2000.L mount, file creation, write, fsync and readback. Its
bounded in-memory server contains only the root and `probe`; it does not
access a host filesystem. Fourteen original native requests and fourteen
sealed replies preserved their message/tag bytes, publication ownership and
birth/completion ordering. The guest and server independently matched the
30-byte file payload, including its terminating NUL, and its flushed bytes.
The run ended at 2,411,391,910,000 ps after 14,400,000 native events. This uses
Linux's documented [VirtIO mount and 9p2000.L protocol](https://docs.kernel.org/filesystems/9p.html),
with uncached file access.

These three functional guest cases do not establish complete device parity,
CPU timing fidelity, coordinated ingress, or full-system exact admission.

All builds and native tests run locally with remote builders disabled. Raw
images, guest traces and kernel diagnostic output remain in temporary storage;
the repository retains source, bounded tests and this concise scope record.
