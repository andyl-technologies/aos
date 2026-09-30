# Inspect runtime abilities and retained execution

`aos ability` reads native module documentation, desired transactions, and
retained execution records. It validates the input before rendering it and does
not evaluate Nix or invoke handlers. See [Runtime abilities](runtime-abilities.md)
for the Nix interfaces and the build, packaging, and activation flow.

Use the development shell or the separately built `aos` binary:

```sh
nix develop
aos ability --help
```

## Browse declarations and desired effects

The same reader accepts generated `aos.package.module-documentation` and
`aos.package.transaction` documents:

```sh
aos ability inspect module-documentation.json
aos ability inspect transaction.json --format json
aos ability inspect transaction.json --format html > transaction.html
aos ability operator transaction.json --serve
```

The reference document describes merged options, operations, handlers, and
package links. A transaction describes the exact desired effects, dependency
order, selected immutable handler programs, and inputs for one deployment.
Neither proves that those effects ran. The local browser uses a loopback
listener and presents the same checked document.

Pass `--expected-digest sha256:<64-hex-digits>` when an authenticated source
supplies an independent digest. The comparison binds the document bytes to that
digest; the source of the digest still determines its authority. Signed package
reference browsing through `apm docs` and Hub authenticates the release and its
native documentation companion before displaying it.

## Compare changes and inspect dependencies

Compare two native documents:

```sh
aos ability compare before.json after.json
```

For transactions with the same scope and platform, the report lists added,
removed, and changed effect identities and whether execution order changed.
Effect revisions are derived from execution-relevant inputs and retained
artifacts. Documentation edits do not change them.

Preview the reverse dependencies of an exact effect key from the transaction:

```sh
aos ability removal-preview transaction.json \
  --effect "$EFFECT_KEY" --max-depth 8 --max-nodes 256
```

This is a bounded desired-graph preview. A truncated result says so explicitly;
it does not establish that removal is safe in the current running system.

## Read committed generations and recovery state

Inspect a committed package profile generation:

```sh
aos ability diagnostic /var/lib/profiles/system 42
aos ability diagnostic /var/lib/profiles/system 42 --audience deployment
```

The default report gives generation, transaction, and result counts. The
`deployment` audience includes desired inputs and retained operation outputs.
These are recorded results, not a fresh query of each service or filesystem
resource. Access to the profile and disclosure of its deployment values belong
to the operator's local authorization policy.

Inspect the native activation journal directly:

```sh
aos ability journal /var/lib/profiles/system/deployment/effects.journal
```

The shared runtime reader validates journal framing and native state transitions
and reports committed state, pending work, and an incomplete trailing frame.
It opens the file for reading and never repairs, truncates, or resumes it.
Recovery is performed by the package transaction controller, which consults the
retained handler's `observe` operation before deciding whether a pending effect
can be retried or accepted.

## Explain realized artifact use

Build gates separately produce `aos.artifact-consumption.evidence/v1` documents
for ELF startup linkage, runtime plugin loading, helper execution, build-tool
execution, and immutable data inputs:

```sh
aos ability artifact-consumption artifact-consumption.json
aos ability artifact-consumption artifact-consumption.json \
  --consumer "$EXECUTABLE" --provider-content "$CONTENT_DIGEST" --format json
```

The report identifies the exact observed files, mechanism, and closure retention.
It does not imply that a native runtime effect was activated. The shared decoder
lives in `aos_doc_model::artifact_consumption`; it is independent of runtime
handler selection and transaction journals.

## Browse through Hub

Hub's native documentation pages and API link package declarations to operations,
selected handler artifacts, and desired effect dependencies. Deployment reports
remain separate from public package references and preserve the reporter's
sequence. A desired transaction is displayed as desired state; committed or
observed status requires corresponding retained execution evidence.

Use [the runtime guide](runtime-abilities.md) for `aos docs runtime`, signed
reference browsing, Hub routes, and the exact artifact schemas.
