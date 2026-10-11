# Explicit authority clock recovery

Authority configuration format 2 initializes a **new journal format 3** with an
immutable `clock_recovery` policy. Configuration format 1 still selects journal
format 2. This workflow does not upgrade, copy or adopt a used format 2 journal.
The installation marker and issuer control protocol remain version 1.

The policy pins an independent Ed25519 reviewer public key and identity, exact
clock uncertainty and commit latency, resource and clock qualification digests,
and a review lifetime of at most 30 seconds. The reviewer must be independent of
the issuer, publisher and renewal roles. This command does not provision keys or
establish deployment qualification from a local clock read or configuration.

```json
{"version":1,"reviewer_key_id":"independent-clock-reviewer","reviewer_public_key":"<64 lowercase hex>","resource_qualification_digest":"<64 lowercase hex>","clock_qualification_digest":"<64 lowercase hex>","maximum_review_seconds":"30","clock_uncertainty":"0","clock_commit_latency":"1"}
```

These example time values are placeholders for independently qualified policy,
not deployment defaults. All input and output documents are bounded canonical
closed JSON. Paths below name existing owner-private inputs or create-new files
in an owner-private output directory.

1. Stop the issuer. Inspect the exact retained resource:

   ```text
   aos-hub-authority inspect-clock-session --configuration CONFIG --output PLAN
   ```

2. Have the independently configured reviewer sign that complete plan:

   ```text
   aos-hub-authority sign-clock-resolution --policy POLICY --plan PLAN --reviewer-seed SEED --output REVIEW
   ```

3. Resolve the exact original under the immutable policy and actual clock:

   ```text
   aos-hub-authority resolve-clock-session --configuration CONFIG --review REVIEW --output RECEIPT
   ```

4. Start the one nominated successor explicitly:

   ```text
   aos-hub-authority serve --configuration CONFIG --clock-resolution RECEIPT
   ```

Automation may perform these explicit operations under its independently selected
operator policy. No interactive approval or inferred default policy is required.
Inspection changes no SQL state. The review binds the full current head, old
session, retained floor and conservative ceiling, immutable policy, file and
parent inode identities, nonce, deadline and nominated successor. Resolution
requires the actual clock interval's earliest time to reach both the retained
ceiling and largest issued expiry, and its latest time to precede review expiry.
Sampling uncertainty includes reviewed commit latency and whole-second rounding.
The actual postcommit sample and monotonic elapsed time are checked before any
receipt is exported.

The issuer and resolver hold a nonblocking exclusive lock on the same pinned
journal inode. The serving lock lasts for the whole clock/service lifetime;
active owners refuse inspection and resolution. This boundary requires qualified
filesystem locking, durable storage and external clock behavior. It provides no
automatic cross-host failover, file cloning or ephemeral-storage portability.
Fresh initialization retains the exact journal and parent inode identities in
the immutable policy record. A copied file refuses inspection before a reviewer
can nominate a successor, even when its installation and policy bytes match.

Resolution appends the exact review and observation without altering installation,
publication history, sequence, expiry or unknown provider effects. It retains the
old nonnull session until an explicit start consumes the receipt atomically and
once. A failed or crashed successor cannot reuse that receipt. Ordinary startup
without a receipt still refuses an unresolved session.

Commit, output or acknowledgment failures never undo retained originals. An exact
resolution retry can recover the unchanged positive only under a fresh qualified
clock before the original review expires. An expired review, changed head, forked
file, unqualified clock, stale original or uncertain successor consumption fails
closed; this first recovery format supplies no automatic replacement review or
history rewrite. Passing the largest lease expiry closes only the old admission
window. It proves no provider drain, settlement or safe object retirement.
