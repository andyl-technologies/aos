# Inspect ability plans and retained execution

`aos ability` reads bounded canonical files and renders checked ability data.
It is a host-side inspection and diagnostic surface. It does not fetch a live
deployment, activate a plan, replay an effect, or change retained state.

The AOS base image does not place `aos` on the operator `PATH`. Use the
development shell or build the `aos` output from a trusted source checkout:

```sh
nix develop
aos ability --help
```

The current command surface has six operations:

| Command | Input | Result |
| --- | --- | --- |
| `inspect` | Portable checked-plan bundle or public-reference inspection input | Checked full graph or bounded slice; plan inputs also support semantic projections |
| `operator` | Inspection bundle and single-focus query; optional observation | Desired and observed operator view as JSON or a loopback browser |
| `diagnostic` | Retained system generation and transaction | Redacted or deployment-detail execution timeline |
| `artifact-consumption` | Realized build-gate evidence | Exact consumer/provider relationship and retention explanation |
| `compare` | Two checked-plan bundles; optional later-plan observation | Runtime-affecting semantic classifications plus the complete structural diff |
| `removal-preview` | Checked-plan bundle and one canonical typed node identity | Bounded reverse-use blockers, required transitions, and retention-only relationships |

## Know what each input establishes

These commands keep reference, deployment, and observation authority distinct:

| Input | What the command checks | What the input does not establish |
| --- | --- | --- |
| Signed package or release reference | `apm` and Hub verify the release; those authenticated readers can wrap its declared contract as `aos.ability.reference-inspection-input/v1` | A selected deployment provider, deployment authorization, or observed runtime state |
| Public-reference inspection input | Canonical encoding, supported public contract semantics, exact package and interface identities, and an optional external input commitment | Authentication of the source commitment, deployment values or grants, or live runtime availability |
| Inspection bundle | Canonical encoding, supported schema, interface and plan semantics, and claimed plan identities | A signed release, reader authorization, current policy, or live execution |
| Inspection bundle plus `--expected-digest` | The same checks plus an exact match to the independently supplied bundle commitment | That the source of the digest is trusted or that its policy is still current |
| Operator observation | Canonical shape, exact plan linkage, known graph identities, and consistent generation comparisons | Authentication of the evidence source, freshness, or a live query of the machine |
| Retained transaction | Protected path traversal, plan-bundle replay, journal framing, and transaction/plan linkage | Independently authenticated journal provenance, pending runtime state, or native execution qualification |
| Artifact-consumption evidence | Realized file facts, exact consumer/provider selectors, mechanism-specific observations, and closure retention | Publication authentication, runtime rebinding, or continued deployment state after an observed invocation exits |

Treat deployment bundles, queries, observations, and deployment-audience
diagnostics as private deployment data. The CLI validates their structure; the
system that supplies them must authenticate the source and authorize the
reader. Public signed reference documentation remains available through
`apm docs` and the release-scoped Hub documentation browser. Those surfaces
authenticate the source before constructing the shared public graph; the
portable wrapper alone does not add release or deployment authority.

## Inspect a checked plan

Render the complete graph as a line-oriented report:

```sh
aos ability inspect inspection-bundle.json
```

Use the global JSON mode or select a format explicitly:

```sh
aos --json ability inspect inspection-bundle.json
aos ability inspect inspection-bundle.json --format dot > ability.dot
aos ability inspect inspection-bundle.json --format mermaid > ability.mmd
```

`--format` accepts `text`, `json`, `dot`, and `mermaid`. `--projection`
restricts the graph to one semantic view:

```sh
aos ability inspect inspection-bundle.json \
  --projection binding-authority --format text
aos ability inspect inspection-bundle.json \
  --projection activation --format dot > activation.dot
aos ability inspect inspection-bundle.json \
  --projection retention --format json > retention.json
```

The projections are `composition`, `binding-authority`, `activation`, and
`retention`. They preserve typed edge meanings; a retention edge does not imply
that the consumer is currently running.

Supply an independently obtained domain-separated bundle digest when the
workflow has one:

```sh
aos ability inspect inspection-bundle.json \
  --expected-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Without `--expected-digest`, semantic validation still runs and the output
identifies the bundle as unanchored. The CLI also warns that its captured
environment and policy are not asserted current. A matching digest anchors the
exact bundle bytes; the command does not verify who supplied that digest.

Use `--query FILE` to return a bounded neighborhood rooted at exact typed node
identities. Query documents use
`aos.ability.inspection-query/v1`, must be canonical JSON with no trailing
newline, and carry explicit direction, depth, and node bounds. Generate them
through the shared `aos-ability-inspect` API or another canonical AOS JSON
producer. The root identities must come from the checked bundle; illustrative
placeholder identities will fail closed.

The same command accepts canonical
`aos.ability.reference-inspection-input/v1` data produced from an authenticated
public package reference. It uses the same `--query`, `--expected-digest`, and
four output formats. Plan-only `--projection` values do not apply. The result's
`public-package-contract` disclosure and limitation diagnostics state that
authorization, conditional deployment requirements, and runtime availability
were not evaluated:

```sh
aos --json ability inspect public-reference-inspection.json \
  --query reference-query.json \
  --expected-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## Build a desired and observed operator view

`operator` requires one canonical `aos.ability.operator-query/v1` document. Its
focus is either one instance or one failing request, and the embedded graph
query must use that same focus as its only root:

```sh
aos --json ability operator inspection-bundle.json \
  --query operator-query.json \
  --expected-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The result always keeps desired plan state separate from observed state. Add a
canonical `aos.ability.operator-observation/v1` overlay when an authorized
collector supplied one for the same exact effect plan:

```sh
aos --json ability operator inspection-bundle.json \
  --query operator-query.json \
  --observation operator-observation.json \
  --expected-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The observation records a capture time and caller-asserted evidence digest.
The CLI does not compare that time with a freshness policy and does not
authenticate the asserted evidence object. States such as `available`,
`failed`, `stale`, and `unverified` report the supplied evidence; they are not
created by polling the deployment.

Serve the same bounded view in a local browser:

```sh
aos ability operator inspection-bundle.json \
  --query operator-query.json --serve
```

The command prints the selected URL and listens on loopback only. Use
`--listen 127.0.0.1:8080` with `--serve` when a fixed local port is needed.
The server keeps the checked source in memory and performs no deployment
authentication, network discovery, or mutation.

## Compare plans and preview removal

Compare two independently obtained checked bundles before applying a desired
change:

```sh
aos --json ability compare before.json after.json \
  --before-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --after-digest sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```

The version-1 comparison classifies visible provider ABI, credential-bearing
operation, enforcement guarantee, aggregate contribution, artifact, transition
strategy, and observed-generation changes. A changed redacted commitment that
cannot be narrowed remains `other-runtime`; it is never called documentation
only. Equal checked plan identities have no runtime-affecting difference, so a
prose-only package documentation rebuild does not request activation.

Use `--observation FILE` only with an overlay collected for the later plan. A
foreign plan is rejected; a diverged or missing generation observation is
classified as `observed-generation`, while failed, stale, or unverified nodes
are `observed-state`. The portable command validates linkage and shape; the
collector remains responsible for authenticating provenance and freshness.

Preview an exact node removal with a canonical JSON-encoded `NodeKey`:

```sh
aos --json ability removal-preview inspection-bundle.json \
  --target provider-node.json --max-depth 8 --max-nodes 256
```

The result separates consumer blockers, controller transitions, and
retention-only relationships. Provider-owned aggregates and resources join the
removal closure before reverse traversal. Reaching either bound sets
`truncated: true` and `blocked: true`; incomplete evidence never authorizes
removal. The preview does not apply the removal or claim that a retained edge
identifies a currently running process.

## Export a retained transaction diagnostic

Each native activation transaction is retained below its system generation.
Pass the canonical generation path and transaction directory name:

```sh
aos --json ability diagnostic \
  /var/lib/profiles/system/gen-42 \
  example-transaction
```

The command requires ownership of every protected path component. Normal AOS
system generations are root-owned, so inspect them through an authorized root
session. Read permission by itself is insufficient, and copying or changing
ownership creates a different diagnostic namespace.

The default `redacted` audience omits normalized inputs, private topology, and
store paths. It retains stable plan and timeline identities for support work.
Use deployment disclosure only after the reader has been authorized for that
deployment:

```sh
aos --json ability diagnostic \
  /var/lib/profiles/system/gen-42 \
  example-transaction \
  --audience deployment
```

Filesystem ownership and protected directory traversal prevent unsafe path
substitution. They do not decide whether a reader may see deployment details.
The deployment audience includes exact replay inputs and topology from the
retained plan; it still does not replay effects or establish current runtime
state.

The timeline provenance is `caller-asserted-journal-anchor`, or
`caller-asserted-journal-prefix` when an incomplete final frame is excluded.
The command never repairs or truncates the journal. Pending state is currently
reported as unavailable because this path reads retained files rather than a
live runtime controller.

## Explain realized artifact consumption

Build gates can emit `aos.artifact-consumption.evidence/v1` for ELF startup
linkage, runtime plugin loading, helper execution, build-tool execution, or an
immutable data input. Inspect one report with:

```sh
aos ability artifact-consumption artifact-consumption.json
```

Use selectors to ensure automation received the intended edge:

```sh
aos --json ability artifact-consumption artifact-consumption.json \
  --consumer /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-consumer/bin/example \
  --provider-content sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

`--format text|json` overrides the output representation. The explanation
identifies the exact provider file and whether the consumer closure retains it.
For observed-path mechanisms it also reports the exact arguments, output hash,
and whether provider access was observed. Read the emitted `limitations` before
using the report: evidence for one mechanism deliberately does not claim the
others, authenticate a signed publication, or prove continued deployment
state.

## Current scope

The current CLI reads version-1 canonical schemas and rejects unknown required
features. It supports offline plan validation and rendering, one-focus bounded
operator views, retained system-generation timelines, and realized
artifact-consumption reports. Remote Hub lookup, signed-release verification,
live controller attachment, activation, effect replay, and state mutation are
outside this command group. Live retained-generation activatability is checked
by the privileged `apm rollback --system --list` and `--dry-run` paths instead.
