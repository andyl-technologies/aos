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
delivery. Its read-only current-cut inspection joins the fixed Controller
writer, actual publisher pointer/revision and authenticated retained `AOSPAUH2`
authorization head. A missing current head reports
`MissingCurrentAuthorization`; no zero epoch, caller-proposed head or packet
signature is promoted to a current grant. Legitimate stale current heads leave
the immutable pair available for exact historical replay only; changed or
malformed delivery and unsafe/corrupt owner state remain rejected. Ordinary
catalog readiness still
does not advertise Source genesis, public Create or a filesystem read grant.

The narrow `NodeController::hold_provisioned_source_genesis_v1` seam borrows its
sole journal and the retained packet input together, then calls the existing
`hold_controller_source_genesis_v1` producer. Only that producer may verify and
retain an administrative authorization/epoch, exact acceptance and settlement
capacity. Its actual pending row fences unrelated Controller mutations and
compaction until genuine Source ACK completion. Startup therefore never calls
the effect seam merely to drop its returned owner: durable admission must wait
until the real coordinator can consume it under one original held interval.

The next coordinator must join the selected immutable Controller/normal-Root
profile to the actual original Root peer/PID1 invocation at a bounded request,
then retain Controller and Source before acquiring Root last. Concurrent
service startup must not require Root to be live during early profile capture.
It must use actual Source append/readback, Controller floor ACK, Source ACK,
Controller completion and final original Root stream consumption in the
existing order, with exact replay after lost replies. No opaque Root client
proof factory or coordinator effect is opened by packet delivery alone.

The authored regressions cover the existing canonical signature leaf and real
bounded file reads/inode substitution. They do not fabricate a fixed production
Controller writer, install privileged credential ancestors, or qualify the
installed PID1 delivery/coordinator. Compilation and execution remain pending.
No Storage initialization, method46 TPM scope, new service/key/capability or
whole-host disk rollback claim is involved.
