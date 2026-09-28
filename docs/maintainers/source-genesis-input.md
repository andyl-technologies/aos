# Provisioned Source genesis input

The existing administrative roles supply two independent signed packets, not
keys or unsigned limits. The normal Controller's optional fixed PID1-delivered
credentials are `controller-source-tree-seed-v1` (`AOSCSE01`, 224 bytes) and
`project-authorization-source-v2` (`AOSPSC02`, 224 bytes). Both must be configured
together with the existing independently provisioned public issuer pins
`controller-source-tree-seed-issuer-v1` (`AOSCSK01`) and
`project-authorization-issuer-v2` (`AOSPAK02`). No in-repository runtime producer
signs a missing administrative decision. Issuance remains privileged external
administrative provisioning; the module only reuses `LoadCredential` delivery.

The protected reader bounds each packet before allocating its contents and
retains its original directory/inode/metadata/bytes. The input checks both
role signatures and equal project, original request, issuer epoch, publisher
generation/pointer and all seven explicit ancestry limits. It forbids key
reuse across roles. These are delivery comparisons, not expected-current
values or epoch admission. `AOSPSC01` is the separate legacy CachePublish
publisher-policy input; it cannot substitute for `AOSPSC02` or ancestry limits.

Startup captures this input after the existing early activation-table capture
and retains it with the actual Controller owner. Rechecks detect changed
delivery. Its separate read-only current-cut inspection joins the fixed Controller
writer, actual publisher pointer/revision and authenticated retained `AOSPAUH2`
authorization head. A missing current head reports
`MissingCurrentAuthorization`; no zero epoch, caller-proposed head or packet
signature is promoted to a current grant. Legitimate stale current heads leave
the immutable pair available for exact historical replay only; changed or
malformed delivery and unsafe/corrupt owner state remain rejected. Ordinary
catalog readiness still does not advertise Source genesis, public Create or a
filesystem read grant.

The narrow `NodeController::hold_provisioned_source_genesis_v1` seam borrows its
sole journal and the retained packet input together, then calls the existing
`hold_controller_source_genesis_v1` producer. Only that producer may verify and
retain an administrative authorization/epoch, exact acceptance and settlement
capacity. Its actual pending row fences unrelated Controller mutations and
compaction until genuine Source ACK completion. Startup never accepts then
abandons a returned owner as ready. The actual executor hook now retains its
real Source writer alongside this journal, joins the independently selected
Root profile to the original connected peer, and opens Root last before
durable admission. It reuses the existing protected Controller-purpose signer;
no administrative key, new service, device, or Root self-report is introduced.

Fresh admission checks the signed seed against the exact prospective
`AOSPAUH2` encoding derived from the real writer's current publisher/request/
epoch state before retaining that authorization. Both original issuer files
stay retained across the effect, and the actual committed current head is
reauthenticated afterward; the prospective value is only a rejection
precondition, never current authority. A read-only original-input/retained-row
selector routes historical genesis recovery before unrelated publisher
bootstrap installation, whose credential may have expired. New admission
still waits until the actual protected publisher policy is installed.

The bounded coordinator uses actual Source append/readback, Controller floor
ACK, Source ACK, Controller completion and final Root Completed/Finish in that
order. Restart rejoins the exact configured original packets and retained rows,
not a regenerated request or seed. Historical receipt/anchored recovery is
separate from current admission; an expired unmaterialized attempt does not
gain append permission. The actual protected publisher policy is sufficient
for this administrative bootstrap: no live Publisher service dependency is
added before Controller readiness. Early profile capture still does not
require Root to be live. Packet delivery alone cannot create either live Root
proof or public Create/read authority.

Source replay is followed by a recheck of the original Root peer, custody and
deadline immediately before effectful Controller input admission. The Source
signer request is explicitly versioned as `AOSSSR08`, carrying data derived
from Root's retained intent or floor. The independent reader checks its actual
pending nonce by reconstructing the canonical intent and comparing the receipt
digest; fresh observation nonces remain separate. After ACK, the exact floor
commitment preserves receipt/role binding. Legacy `AOSSSR07` is rejected, and
global Empty requires the entire Source journal to contain no records.

The authored regressions cover the existing canonical signature leaf and real
bounded file reads/inode substitution. They do not fabricate a fixed production
Controller writer, install privileged credential ancestors, or qualify the
installed PID1 delivery/coordinator. Additional pure deadline, phase, nonce,
completion-digest and disconnected-queue regressions do not fabricate Root
owner custody. Protected Source journal regressions cover cold append/replay,
fresh correlation with an unchanged original nonce, altered UID/roles/accepted
input, post-ACK role binding and unrelated-row Empty refusal. They are not
installed Root flight or crash-injection qualification. Rust compilation and
execution remain pending.
No Storage initialization, method46 TPM scope, new service/key/capability or
whole-host disk rollback claim is involved.
