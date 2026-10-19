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

The separate source descendant retains original CPU byte/scalar and nested
getter results, a versioned cached CPU reader, source-owned PIT/LAPIC records,
and an original system-file resource-policy prefix. Every preceding notice is
retained. Its constructor resource quote has incomplete coverage and refuses
selected VM creation before FD-table allocation. Availability, RUN and Ready
remain unsupported; source byte closure does not establish runtime admission.

| Added source role | SPDX notice |
| --- | --- |
| `arch/x86/kvm/crucible-pic-initializer-nested-output.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-cpu-output-reader.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-ps-pit-apic.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-ps-pit-producer.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-ps-pit-watchdog.inc.c` | `GPL-2.0-only` |
| `arch/x86/kvm/crucible-q35-ps-timer-bank.inc.c` | `GPL-2.0-only` |
| `virt/kvm/crucible-original-kernel-resource.inc.c` | `GPL-2.0-only` |
| `virt/kvm/crucible-q35-ps-pit-route.inc.c` | `GPL-2.0-only` |

The explicit original Task allocator/refusal source stages add two private GPL
roles and preserve every existing native MM/Task license notice. Their callback
owners, original Task/mm/file/module references and allocation journals remain
kernel-private; no process protocol carries those native objects.

| Added source role | SPDX notice |
| --- | --- |
| `include/linux/crucible_allocator.h` | `GPL-2.0-only` |
| `mm/crucible_allocator.c` | `GPL-2.0-only` |

These stages cover only original control-delivery metadata and explicit refused
allocator paths. Actual aggregate physical peak/backing retirement remains
incomplete. Source41 currentness precedes mask observation; historical Source40
is retained as its separately inspectable predecessor. Constructor coverage
stays bit0 and selected CREATE_VM is refused before native allocation. Full
Kbuild/module/guest execution, RUN and Ready remain unqualified.

Source42 changes four existing native roles without adding or removing a source
file or changing its license notice. Its literal original VM-root constructor
retains vendor request geometry, Task/file/generation custody and native
allocation/cleanup outcomes. Request reservation and final-pointer observation
do not complete physical peak or backing retirement. Constructor coverage stays
bit0, required coverage stays 2047, and no selected CREATE/RUN/Ready permission
is issued. The complete source/config/toolchain retention policy is unchanged.

Source43 modifies the existing native vmalloc file and existing private allocator
header/core and kernel resource include. No source file is added or removed; all
per-file notices remain intact. Its original vm_struct birth, exact deferred work
and cleanup receiver tokens remain kernel-private. Callback return is not
physical backing retirement; original Unknown charges/references stay held.

| Modified existing native role | SPDX notice |
| --- | --- |
| `mm/vmalloc.c` | `GPL-2.0-only` |

The selected source roster includes this existing upstream role from its exact
archive preimage before every stage. Current coverage stays bit0, required
coverage stays 2047, selected CREATE stays fenced before descriptor allocation,
and no continuation/RUN/Ready permission is issued. Full native Kbuild, workqueue
execution, physical budget and retirement remain unqualified.

Source45 adds original per-CPU deferred-vfree list/work/method custody and corrects
its original canonical address lineage. It modifies only existing GPL roles;
no native file is added or removed and all per-file notices remain intact.
The first canonical address is immutable, exact repeat is observational, and
unrelated replacement stays sticky Unknown before constructor return. The
known faulty private Source44 is excluded from this production chain.

Native IRQ/workqueue/per-CPU allocation, shared physical backing and retirement
remain unqualified. Coverage stays bit0, required coverage2047, and selected
CREATE remains refused before descriptor allocation; RUN and Ready stay closed.

Source47 is the corrected Source45 descendant for a dedicated boot-born per-CPU
constructor pool and source-owned post-observer delivery. The blocked private
Source46 payload is not a production stage. All 36 preceding patches remain
byte-identical. No existing source file or notice is removed.

| Newly catalogued source role | SPDX notice |
| --- | --- |
| `mm/percpu.c` (modified existing upstream role) | `GPL-2.0-only` |
| `mm/crucible-percpu-pool.inc.c` (new private include) | `GPL-2.0-only` |

The source roster checks the original upstream per-CPU allocator before every
stage. Exact raw GFP_KERNEL precedes selected effects; original native output
and a single final observer precede the retained delivery/currentness cut.
Owner, callback, Task, alias and output-row addresses stay kernel-private.
The pool bound covers its symbol slices/template/mapping metadata/keeper, not
whole first-chunk allocation, unused unit/group slack, NUMA padding or boot peak.
Actual boot, IRQ/concurrency, physical budget and complete SRCU remain unqualified.
Coverage remains bit0, required coverage 2047, and selected CREATE remains fenced
before FD allocation. No continuation, RUN, support bit or Ready is issued.

Source48 retains the literal embedded first-chunk group allocation lineage and
its complete padded CPU map before native group allocation/publication. It
modifies existing per-CPU/private allocator source and adds one private include;
all existing notices and 37 preceding patch payloads are unchanged.

| Added source role | SPDX notice |
| --- | --- |
| `mm/crucible-percpu-first-chunk.inc.c` | `GPL-2.0-only` |

Original group tokens/results and native CPU/group metadata remain kernel-private.
Conservative original group-request charges include padding/tails without trim
refunds; virtual NUMA gaps stay separate from allocated bytes. This does not
qualify complete first-chunk setup metadata, memblock internal/retry/resize,
page-remapped boot, concurrency/PFN/maps or global boot physical peak.
Coverage remains bit0, required coverage2047, and selected CREATE remains fenced
before FD allocation. No continuation, support bit, RUN or Ready is issued.

Source50 adds the corrected cumulative original boot metadata and memblock
retry/resize accounting from Source48. All 38 preceding payloads and existing
source notices remain unchanged; rejected Source49 is not an ordered stage.

| Added or newly catalogued source role | SPDX notice |
| --- | --- |
| `include/linux/crucible_percpu_boot.h` | `GPL-2.0-only` |
| `mm/crucible-percpu-boot-accounting.inc.c` | `GPL-2.0-only` |
| Modified existing `mm/memblock.c` | `GPL-2.0-or-later` |

The persistent kernel-private ledger retains original metadata roles, native
range retry and overlapping old/new resize observations. First raw results are
retained before post-native completion reconciliation; allocation and final
resize observations stay separate. Cumulative page-rounded attempts deliberately
overlap, with no refund or complete global physical peak claim. The currently
configured object contains 552,960 bytes of boot keeper storage; this source
measurement is not a native Kbuild/boot guarantee. Platform acceptance, PFN/maps,
global boot and concurrent IRQ/async lifetimes remain outside qualified scope.
Coverage stays 1, required coverage 2047. Selected CREATE is refused before FD
allocation; no continuation, capability support, RUN or Ready is issued.

Source51 accounts for native region-array resize caused by first-chunk trim and
cleanup. All 39 earlier payloads and notices are unchanged. It modifies the
existing private header/include and existing GPL-2.0-or-later `mm/memblock.c`;
no source file or licensing scope is added or removed.

A source-born original free scope retains its allocation/resize lineage before
native removal, including nested old/new array charges and the native integer
result before completion reconciliation. There are no byte refunds or renewed
physical incarnations from address reuse. The configured boot keeper measures
798,720 bytes; this is component object geometry, not complete native boot peak.
Native remove/isolate, platform backing, PFN/maps and concurrent IRQ/async
lifetimes remain unqualified. Coverage stays 1 of required 2047, with selected
CREATE fenced before descriptor allocation and support/RUN/Ready closed.

Source52 adds the original post-initialization per-CPU backing issuer. All 40
prior payloads and notices remain unchanged. Existing private pool source and
`mm/percpu.c` retain their notices; one private include is added.

| Added source role | SPDX notice |
| --- | --- |
| `mm/crucible-percpu-backing.inc.c` | `GPL-2.0-only` |

The actual built-in late initializer retains source-born runtime arena and
permanent keeper page references after page metadata exists. Native pin results
are retained before reconciliation, with no uncertain-prefix unpin or renewal.
The original linker template has init lifetime and remains historical only.
The backing bank's configured object measurement is 675,840 bytes, separately
from the 798,720-byte boot ledger; neither measures complete native boot peak.
Full Kbuild, native boot/hotplug/PFN lifetime and global physical resources remain
unqualified. Coverage mask stays 0x001; required mask 0x7ff has 11 domain bits.
Selected CREATE remains fenced before descriptor allocation; no capability
support, RUN or Ready is issued.

Source54 adds the original whole-CREATE scope and closes retained system-file
address reuse. All 41 prior payloads and notices remain unchanged; no new
native source file is added. Existing `virt/kvm/kvm_main.c` retains its upstream
SPDX/notice, and `virt/kvm/crucible-original-kernel-resource.inc.c` retains
`GPL-2.0-only`.

The literal ioctl wrapper enrolls original Task/mm/system-file/files/generation
before descriptor allocation and retains raw returns before reconciliation.
An original files reference spans this call and is dropped outside the scope;
attempted context history is retained. Closed origins leave live lookup while
late completion authenticates retained array membership and generation.
The configured whole TU and modeled-peer controls do not prove native FD-table,
anonymous-file, shared backing, RCU retirement or whole physical resource limits.
Coverage stays 0x001; required 0x7ff is an 11-bit mask. The selected constructor
still refuses before FD allocation; no native continuation/delegation, capability
support, RUN or Ready is issued. Historical Source53 is not a production stage.


The original FD-table/allocator-retirement stage adds three private kernel roles
and catalogs two existing upstream roles. All earlier patches and notices remain
unchanged. Native pointers, tokens and callbacks remain kernel-private.

| Added private role | SPDX notice |
| --- | --- |
| `include/linux/crucible_fdtable.h` | `GPL-2.0-only` |
| `fs/crucible_fdtable.inc.c` | `GPL-2.0-only` |
| `mm/crucible_allocator_retirement.inc.c` | `GPL-2.0-only` |

Existing `fs/file.c`, `include/linux/fdtable.h` and `mm/slub.c` retain their
complete original `GPL-2.0` notices. Existing allocator/resource roles retain
`GPL-2.0-only`. The FD source-control template and ordinary control are
`GPL-2.0-only` test source; they are not a kernel execution witness. No QEMU file
or permissive process protocol is changed.

The exact 43-stage/182-role kernel roster and all new test/build source are
retained by the existing complete source/config/toolchain companion policy.
Publication still requires the matching same-build source output. Constructor
coverage remains `0x001` of required `0x7ff`; FD_TABLE, selected CREATE, active
execution, state preservation, RUN and Ready remain unsupported. Configured
object compilation, source-consumer tests and ordinary build-host FD tests are
separate from full Kbuild/link and actual patched-kernel runtime qualification.
