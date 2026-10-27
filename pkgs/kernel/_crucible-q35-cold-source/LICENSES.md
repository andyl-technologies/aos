# Reviewed native initialization source licenses

The component changes Linux kernel source and preserves every existing file's
license notice. It does not link QEMU into the Apache host or change a permissive
process protocol to carry native objects. The ordinary controller/PIC patch
chain and its complete MIT notices remain prerequisites.

| Source role added by this component | SPDX notice |
| --- | --- |
| `arch/x86/kvm/crucible-pic-board-constructor.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-pic-device-birth.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-pic-initializer.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-pic-initializer-roster.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-pic-vm-setup.inc.c` | `GPL-2.0-only` |
| `virt/kvm/crucible-pic-memory-initialization.inc.c` | `GPL-2.0-only` |

The existing UAPI header retains `GPL-2.0 WITH Linux-syscall-note`. Its public
structures contain fixed-width numeric values, bounded public architectural
bytes and reserved fields. Actual kernel tasks, vCPU objects, route tables,
callback pointers and input/output journals remain private kernel objects.

The retained native source uses GPL-2.0-only kernel scope. Portable verifier
scripts check source and compiler records and are not linked into the kernel,
QEMU, or a host protocol crate. No QEMU files are added or removed by this
component; future QEMU worker/frontend additions need their own QEMU license
inventory and matching corresponding-source release artifact.

The cumulative Q35/CPU/counter/PS bridge adds these private GPL kernel roles:

| Source role | SPDX notice |
| --- | --- |
| `arch/x86/kvm/crucible-pic-initializer-cpu-bytes.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-bootstrap-clock.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-device-initializer.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-inactive-clock.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-initial-routing.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-loaded-counter.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-msr-filter.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-pit-bootstrap-arm.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-ps-clock.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-ps-native-cut.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-vm-configuration.inc.c` | `GPL-2.0-only` |
| `include/linux/kvm_crucible_ps_clock.h` | `GPL-2.0-only` |
| `virt/kvm/crucible-q35-memory-effects.inc.c` | `GPL-2.0-only` |

Every existing notice is retained, including complete PIT/PIC MIT notices and IOAPIC LGPL scope. Native tasks, callbacks and objects remain kernel-private. Cap43 availability and selected RUN remain unsupported; no whole-clock, physical output seal or Ready follows from this source closure.

Typed PS IRQ and native timer closure add these private GPL roles:

| Source role | SPDX notice |
| --- | --- |
| `arch/x86/kvm/crucible-q35-pit-ps-adoption.inc.c` | `GPL-2.0-only` |
| `virt/kvm/crucible-q35-ps-irq-input.inc.c` | `GPL-2.0-only` |

Cap43/45 availability and selected RUN remain unsupported. These original source journals do not issue active clock, physical output or Ready authority.
