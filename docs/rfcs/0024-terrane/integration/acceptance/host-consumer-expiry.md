# HOST-24 consumer-expiry component audit

This audit records qualified component evidence for HOST-24. It does not accept
T-HOST-1 or the complete host-tier deployment. HOST-24 remains part of the
T2–T6 trunk even though the optional topology expiry workline is excluded.

## Requirement and implementation

HOST-24 requires periodic release of pins belonging to an expired lease owner,
so those pins cannot block eviction beyond release grace. The native owner
implements that policy in `host_cache/owner/consumer/sweep.rs`:

- The effective deadline is the earlier of the pin and owner-lease deadlines.
  Ordinary expiry uses that original deadline plus configured release grace.
  An explicit-release grace record already includes grace and receives no
  second interval. Delayed sweeps never restart the interval.
- The physical worker in `host_cache/owner/retention.rs` calls the sweep before
  processing commands and after a one-second idle receive timeout. Callers do
  not need to submit a sweep request to trigger cleanup.
- The sweep checks the original Running context, registered jobs, physical
  custody and durable policy. It revokes affected views, persists the removal,
  synchronizes backing and policy, and releases only matching consumer holds.
  Unrelated producer obligations and physical backing remain owned.
- Exposure custody is separate. Expiring an exposure starts draining; it does
  not establish closure of retained descriptors or mappings, or permit their
  physical charges to be discharged (D-133).

Rust paths above are relative to
`crates/terrane/linux/terrane-linux/src/`.

## Reviewed guest evidence

The complete all-feature native cache qualification at
`4cf7001d46b295d4ba6d29d2e79e62341789788e` passes in 1,593.357 seconds.
Its aggregate is
`/nix/store/j7af5ba8iksjy0ldvk89qqjkzpsm1269-terrane-native-host-cache-all-features-scenarios-0`.
Review matches all 8,240 immutable source files, 5,502 bound inputs and four
retained actual Cargo executables across the three independent guests. The
unit guest executes 257 ordinary cases and five capability-free creator cases.

The recovery guest is
`/nix/store/alin1xzyn5i7c7740iacv87spk23vrg9-aos-vm-test-terrane-native-host-cache-all-features-recovery-ext4-0`.
Its serial log SHA-256 is
`a3ab055bac500f91bb9c00e7866d3ee49d56c23e1ffcdc1bcc9f11528d3c4f53`.
The original `consumer-leases` fixture and independent supervisor establish:

- An acknowledged consumer pin, lease and distinct future hold protect the
  original immutable inode. Reads continue while policy access is held.
- Dropping an accepted renewal waiter does not cancel its durable update.
  Stopping the actual quota helper prevents premature policy mutation; after
  continuation, the supervisor observes the exact renewal without another
  request manufacturing completion.
- Explicit release followed immediately by a new consumer retains the first
  consumer's original grace and adds a distinct grant without duplicating
  physical backing. The supervisor checks exact durable records and bytes.
- The expired grant refuses reads and renewal. Its durable protection remains
  until grace. The fixture then sleeps through the original deadline without
  issuing a sweep or retry; the background worker removes exactly its consumer
  pins, leases and holds. Independent policy inspection matches the original
  producer baseline and verifies the same inode and plaintext.

Both the fixture and independent supervisor emit their exact completion
witnesses; the guest reports `TEST_RESULT:PASS` and successful Firecracker exit.
Native filesystem, quota and confinement operations execute inside the guest.

## Expiry through physical eviction

Renewed all-feature cache qualification at
`ff940f1b3fe1825c552a00ec85260ad7e02ef531` passes in 1,625.633 seconds.
Its aggregate is
`/nix/store/icfcij6lfvp42y2953pspqys658n77ra-terrane-native-host-cache-all-features-scenarios-0`.
Complete review matches 8,246 immutable source files, 5,505 bound inputs and
four retained actual Cargo executables across all three independent guests.
The unit inventory remains 257 ordinary and five creator cases.

The renewed recovery guest is
`/nix/store/21qnyw72c6sf0phiql1gnsng5njk4l0g-aos-vm-test-terrane-native-host-cache-all-features-recovery-ext4-0`.
Its serial log SHA-256 is
`6f194f2897db6fb7f10fda6a37ce3a22d299603bd344f5aceb2167ce9677202e`.
The `source-cleanup` fixture and independent supervisor now additionally verify:

- A finite consumer remains retained while its original lease expires. No
  explicit release or sweep is issued for that consumer. The ordinary worker
  removes its exact durable pin, lease and hold after the effective deadline
  and release grace; independent inspection observes the removal before
  retirement of the original inline inode.
- Original queued-pin, restoration, unrelated-consumer and release-grace
  controls still run. After the remaining eligible protections close, the
  original inline object is evicted and measured physical usage falls while
  the expired consumer handle remains retained.
- The original last-descriptor and quota observations still establish actual
  reclamation. Both new completion witnesses occur in the actual guest log,
  followed by `TEST_RESULT:PASS` and successful Firecracker exit.

This closes the earlier component gap between periodic expiry and physical
eviction for the exercised inline-object scenario. It also qualifies the
cache suite against the intervening read-only coordination and repository-open
changes; the historical evidence above remains unchanged.

## Remaining acceptance boundary

Configured service deployment, retained-kernel-reference accounting and the
other T-HOST-1 requirements still require their complete audits and integrated
qualification. Consumer-handle expiry does not establish closure of retained
exposure descriptors or mappings (D-133). No task checkbox or accepted-task
count changes follow from this component audit.
