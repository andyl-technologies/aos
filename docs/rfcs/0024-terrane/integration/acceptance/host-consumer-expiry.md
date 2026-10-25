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

## Remaining acceptance boundary

This proves the exercised periodic consumer-expiry lifecycle. The scenario
deliberately preserves producer custody, so it does not prove that an otherwise
eligible object is physically evicted after the final expired consumer pin.
Physical eviction, retained-kernel-reference accounting, configured service
deployment and the other T-HOST-1 requirements need their own complete audits
and integrated qualification. The evidence above predates the read-only
coordination fix at `9d89554155`; it does not qualify that fix. No task checkbox
or accepted-task count changes follow from this component audit.
