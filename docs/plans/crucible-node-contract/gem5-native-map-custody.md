# Gem5 native map custody

A real gem5 checkpoint exposes a DMTCP process-map record larger than the
ordinary 64 KiB lookup envelope. The original SET operation also returns the
complete previous value, even when its caller does not use that reply.
Truncating either direction would lose state needed for exact restoration.

The selected writer negotiates separate map-transfer messages with a finite
1 MiB bound in each direction. Its original request and complete old-value reply
remain on the same owned socket and retain their original identity. Constructor,
header, exchange, candidate and parked storage are charged before effects.
Partial transfer after mutation remains Unknown with its original charge; it
does not rerun the setter. The ordinary 64 KiB path retains its existing behavior.

The complete map bank is included in the versioned five-section source capsule,
alongside the coordinator log, control account, restart script and original link
storage. The capsule and borrowed reader have separate finite bounds. Native
source roles retain their applicable LGPL notices, and the selected package
co-retains the complete corresponding source, all previous patches, controls,
recipe and license inventory.

Independent review covers all 15 native source roles and the six package files.
The matching ordinary package and source build passes in 26.07 seconds, including
its original application, checkpoint and two fresh restoration checks. The
separate package check passes six authored component groups and compiles the
borrowed capsule reader in 6.47 seconds. The installed source preserves all 549
previous files except seven declared modifications and adds eight native files.

Separately, the real gem5 test workload produces a complete checkpoint and
map/capsule journal while its original threads remain held. That capture does
not qualify whole-node native issuance or two operative restored gem5 branches.
Those restorations, full-system guests, device parity and common readiness still
require their own integration and qualification. Raw artifacts stay local.

## Original thread identity and launch diagnostics

The selected thread-owner binding reads its identity through the raw kernel
adapter. DMTCP's next syscall symbol can return a virtual thread ID, which must
not be compared with the owner's kernel identity. The ordinary `Thread::tid`
and PID plugin retain their existing virtualization behavior.

A fresh complete-source diagnostic configures, builds and installs in 3.41,
26.82 and 0.82 seconds. Its selected launcher/library exec observation passes
with the same kernel child, then observes exact original cancellation by
SIGKILL and coordinator refusal on the closed selected channel (exit86).
A separate ordinary unselected application and coordinator both exit0.
Each native producer owns a distinct empty mode-0600 console. Normalized
package diagnostic sources compile with warnings treated as errors, and the
required source-owner check runs both lifecycles.

Independent review verifies the source delta, preserved native features and
corresponding-source/license inventory. Earlier failed startup assertions stay
recorded separately. The ordinary package, complete production journal, native
cut, checkpoint issuer, restored adoption and readiness remain unqualified.
The helper's libc `system()` shell path is a separate outstanding hermeticity
requirement; these diagnostic controls do not establish its correction.
