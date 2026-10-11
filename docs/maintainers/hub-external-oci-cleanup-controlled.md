# Controlled versioned OCI cleanup fixture

The External OCI connected test uses a local Node TLS S3 fixture with real
stored versions, strong ETags, verified SigV4 requests and persistent Worker
objects. It does not exercise Garage, hosted S3 or Managed R2 SDK deletion.

Before admitting a Delete cohort, a separate bootstrap Worker retains the
actual queued credential and the Native topology controller executes its
purpose probe. The fixture starts that credential as `unknown`; only the
controller's authenticated result records `valid`. After the admitted
publication and issuer are installed, the ordinary conditional-delete probe
writes two different reserved objects, rejects the stale ETag, deletes the exact
current version, verifies its exposed predecessor and removes that version.
The resulting SQL capability names the actual binding, write revision and
Delete generation. No fixture initializes a valid conditional-delete flag.

The provider retains at most 128 actual versions and 64 MiB of object payloads,
with a 20 MiB limit per object. These are fixture retention bounds, not Worker
memory measurements. Object deletion requires both its actual stored version
and strong `If-Match` ETag. The absent service-owned credential probe is a
separate operation and cannot delete any business object.

The connected test withholds one authenticated positive cleanup response after
the Worker has retained it. The existing cold Worker restart occurs before the
Native cleanup retry, which must settle from the same positive receipt without
another provider request. SQL chunks remain immutable after the all-upload
cleanup CAS clears its locators. A distinct terminal original loses the actual
provider DELETE acknowledgement; subsequent cleanup requests must refuse and
leave SQL pending without HEAD or DELETE redispatch.

## Evidence scopes

The provider's three Node HTTP tests exercise exact selectors, wrong and
missing selector refusal, retained version history, bounded storage and a lost
provider response. They do not execute the Worker or establish SQL capability.
The Native test compile establishes only that the genuine controller and
cleanup fixture are wired. Connected assertions and their private receipts are
pending until a matching Worker artifact and actual runtime are selected.

Keep the prior OCI pilot and its unknown originals intact. Run this extension
only in a fresh private fixture directory, using independently selected
source-built Node, workerd, Native test executable and Worker distribution.
Retain each tuple's source census and actual artifact hashes. The test is
`storage_work::external_oci::tests::actual_external_oci_blob_config_manifest_index_tag_and_cold_replay`
and remains explicitly ignored outside this controlled invocation.

The same-five-machine Garage installation lacks the necessary versioned
read/delete contract and must remain unsupported. Managed R2 terminal cleanup
requires a distinct actual SDK gate and independently valid Delete capability;
OCI-only emulator acceptance does not supply ordinary Managed Delete authority.
