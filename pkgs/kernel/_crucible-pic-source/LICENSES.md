# Native PIC source component licenses

These Linux source patches preserve existing per-file notices. New private kernel
helpers carry the GPL-compatible SPDX notices listed below. Source-extracted test
programs combine GPL-2.0-only inputs with MIT PIC portions; their generated source
retains the complete original MIT copyright and permission notice. No QEMU code
is linked into the Apache host or included by permissive protocol crates.

| Source path | Status | Retained or added notice |
| --- | --- | --- |
| `arch/x86/kvm/crucible-apic-target.inc.c` | new | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `arch/x86/kvm/crucible-clock.c` | existing | // SPDX-License-Identifier: GPL-2.0-only |
| `arch/x86/kvm/crucible-clock.h` | existing | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `arch/x86/kvm/crucible-ioapic-eoi.inc.c` | new | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `arch/x86/kvm/crucible-ipi-source.h` | new | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `arch/x86/kvm/crucible-irq-device-access.h` | new | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `arch/x86/kvm/crucible-irq-injection.h` | new | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `arch/x86/kvm/crucible-lapic-timer-ancestry.inc.c` | new | // SPDX-License-Identifier: GPL-2.0-only |
| `arch/x86/kvm/crucible-pic-run.h` | new | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `arch/x86/kvm/crucible-pit-ancestry.inc.c` | new | // SPDX-License-Identifier: GPL-2.0-only |
| `arch/x86/kvm/crucible-x2apic-ipi.inc.c` | new | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `arch/x86/kvm/i8254.c` | existing | MIT; complete original copyright and permission notice retained |
| `arch/x86/kvm/i8254.h` | existing | /* SPDX-License-Identifier: GPL-2.0 */ |
| `arch/x86/kvm/i8259.c` | existing | MIT; complete original copyright and permission notice retained |
| `arch/x86/kvm/ioapic.c` | existing | // SPDX-License-Identifier: LGPL-2.1-or-later |
| `arch/x86/kvm/ioapic.h` | existing | /* SPDX-License-Identifier: GPL-2.0 */ |
| `arch/x86/kvm/irq.c` | existing | // SPDX-License-Identifier: GPL-2.0-only |
| `arch/x86/kvm/irq.h` | existing | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `arch/x86/kvm/lapic.c` | existing | // SPDX-License-Identifier: GPL-2.0-only |
| `arch/x86/kvm/lapic.h` | existing | /* SPDX-License-Identifier: GPL-2.0 */ |
| `arch/x86/kvm/x86.c` | existing | // SPDX-License-Identifier: GPL-2.0-only |
| `include/linux/kvm_host.h` | existing | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `virt/kvm/irqchip.c` | existing | // SPDX-License-Identifier: GPL-2.0-only |
| `arch/x86/include/asm/kvm_host.h` | existing | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `include/linux/kvm_crucible_clock_continuation.h` | new | /* SPDX-License-Identifier: GPL-2.0-only */ |
| `include/uapi/linux/kvm.h` | existing | /* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */ |
| `virt/kvm/crucible-initialization-observation.inc.c` | new | // SPDX-License-Identifier: GPL-2.0-only |

The source closure also retains the original Stage7 GPL declarations in `include/linux/kvm_crucible_clock_math.h` and `include/linux/kvm_crucible_completion.h` unchanged.

| `virt/kvm/crucible-clock-continuation.inc.c` | new | `GPL-2.0-only` (original SPDX notice retained) |

Original EOI source additions retain their GPL notices:

| Source path | Status | Notice |
| --- | --- | --- |
| `arch/x86/kvm/crucible-pic-eoi.inc.c` | new | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-pit-pic-ack.inc.c` | new | `GPL-2.0-only` |

The retained release predecessor is source-only `GPL-2.0-only` counterfactual
input. All seventeen EOI model variants retain the complete original PIC MIT
notice together with their copied GPL-compatible inputs. The timestamp peer
covers actual-produced nonnegative birth values, not arbitrary forged values.

Deferred PIT publication changes four existing native roles and retains every
original SPDX notice. Its ten source-extracted models retain GPL-2.0-only scope;
PIC geometry and partial row fields are explicit modeled peers, not copied MIT
PIC routines. The prior receiver and original EOI models retain their complete
MIT notices and are generated at their original source checkpoints.
