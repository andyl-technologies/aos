# External destinations for Git registry mirrors

Full and pull-through mirrors can select an admitted External S3 destination.
The source remains a public signed registry using the supported `refs/*`
configuration. Required signature verification, configured trust roots, and
the existing refusals of secret-backed upstream authentication and other
refspecs still apply.

## Destination requirements

The current binding, surface writer, and credential revisions must agree with
the independently accepted External profile. Read, List, and Write cohorts
must be installed for that exact authority, association, executor, and physical
prefix. A Mirror purpose document additionally commits the installed transport
domain and the independently reviewed conditional-read and upload behavior.
An accepted Direct Write profile alone does not authorize a Mirror workflow.

The physical executor supports two separately qualified identity modes:

- Versioned destinations retain the actual provider version, strong ETag, and
  byte size returned by the provider.
- Guarded versionless destinations retain an authenticated physical closure,
  strong ETag, and byte size. A guard incarnation is never a provider version.

Zero-byte representations also require independently qualified create-only PUT
identity. Unsupported required capabilities refuse the affected workflow.

## Publication and retained cleanup

Worker performs the upstream fetch, private staging, full hash and optional NAR
verification, and destination materialization. Native receives bounded control
results and independent final evidence, then commits the catalogue beneath
current SQL admission and credential fences. Immutable objects precede mutable
pointers. Pending provider intents remain fenced after cancellation, expiry, or
an unknown response; a retry cannot silently allocate a replacement stage.

A successful External publication retains its exact private stage and immutable
receipt journal with `retained_for_qualified_cleanup`, including the actual key,
identity, and byte cost. This path dispatches no unqualified Delete or Abort.
An exact terminal replay returns the retained commit without a new stage or
provider mutation. Later cleanup needs independently qualified Delete authority;
retained stage bytes do not imply physical drain. Managed cleanup is unchanged.

## Local functional qualification

The do-e2e Worker can load a separate signed
`full_and_pull_through_functional_probe_v1` document for one reserved
`.aos-mirror-qualification/<run>/final/{full,pull-through}` namespace. It binds
the actual current External prerequisite, installed source and script, public
origin, provider report, process/configuration observations, object ceiling, and
original cutoff. Its reviewer and readback key are independent of the Direct
reviewer and physical mutation key.

The Native helper installs this document only through its explicit
`mirrorFunctional` private artifact/reviewer/readback-key triplet. The controlled
metadata transport permits only the signed fixture upstream; ordinary public
upstream address restrictions remain in force. The helper runs the real due
Mirror Sync controller, so a queued Sync response is not completion evidence.

Ordinary Worker builds reject this emulator purpose. A local functional result
does not establish Hosted acceptance, whole-workload Native byte safety, memory
limits, throughput, or provider drain. Those qualification gates remain separate.
