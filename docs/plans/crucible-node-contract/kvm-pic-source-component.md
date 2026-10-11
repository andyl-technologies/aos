# KVM original PIC consumption source component

`linux-controller-pic-source-check` checks the original PIT pulse's bounded PIC
receiver, intack and architecture injection tail. It builds eight x86 source
objects and extracts one positive and eleven guard-removal controls from the
same patched source. A negative control passes only after compiler success and
an abort at its exact original assertion location. Compiler errors and timeouts
fail the check.

The check applies the existing controller patches 1–7 first. The two patches in
`pkgs/kernel/_crucible-pic-source/` then retain the previously tested source
prerequisites and the PIC component. A closed inventory verifies every source
preimage and postimage; application rejects fuzz and offsets. The prerequisite
patch includes the authentic continuation, memory/IRQ admission, timer ancestry,
IPI/destination and original acknowledgement source inputs needed by these
objects. It is an object-source composition, not a complete linked kernel.
Existing Stage7 two-ISA and original ABI checks remain a required independent
build dependency.

Native objects run serially with the original AOS kernel configuration, including
`CONFIG_WERROR=y`. Models retain the original flags and complete PIC MIT notice.
Each command has a fresh 2 GiB disk floor; native and model output share a 64 MiB
budget. Native compilation and model compilation have 300-second bounds; model
execution has a 30-second bound. The first failure stops the sequence and keeps
its original output. Model reports retain partial command history on failure.

The original generation, PIT birth, target RUN owner, vector and PIC geometry
remain bound through local intack and final architecture reconciliation. A late
final failure leaves the original receiver Unknown before its effect credit is
released. `CONSUMED` records the native routine's injection tail, not proof that
a guest received or handled the interrupt.

The privately tested predecessor composition compiled all eight objects and
passed the positive plus eleven intended assertion-abort controls. Its exact
source and actual artifacts received independent review. The separate hermetic
repository check also passed all eight configured source-object checks, one
positive model and eleven intended assertion-abort controls. The checked source,
reports and resource limits received independent review. This realization uses
repository-owned patches and fixtures, with no retained private build paths or
historical test executables.

This package emits check reports. It installs no kernel or module and runs no
virtual machine. The PIC producer dispatcher, original PIC EOI, ordinary dual
PIC/IOAPIC routing and coalescing, complete FirstBegin board admission and kernel
linking remain unqualified. The existing unsupported IRQchip prerequisite is
retained. This component supplies no Ready, execution grant, complete device
closure, preservation or hardware qualification.
