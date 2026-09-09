# Documentation, inspection, and generation operations

## Explain the contract through existing tools

The public value is a concrete answer to "what will this package do here?"
Users should not need to navigate a whole-system graph to find a missing
credential, unsupported manager, or incompatible provider.

At the baseline, package documentation belongs to `apm docs`, not an `aos docs`
command. AOS, APM, and APR are separate entry points. Extend the relevant
existing surfaces rather than introducing command aliases by implication.
The [documentation implementation](../../../crates/aos-package/src/documentation.rs)
and [shared model](../../../crates/aos-doc-model/src/lib.rs) already support
exact package documentation and runtime/effect metadata.

Three kinds of information must be visibly distinguished:

| Information | Authority and scope |
| --- | --- |
| Package reference | Authenticated release's declared interfaces, requirements, configuration, and semantics |
| Deployment plan | Exact selected providers, grants, artifacts, and proposed effects for one environment |
| Observed state | Timestamped evidence about actual activation, health, and resource assignment |

A package reference can say that nginx supports TLS credentials. Only a
deployment plan can identify the selected credential binding. Only runtime
evidence can establish that the new service revision was observed ready.

## CLI inspection and diagnostics

Enhance existing package inspection and the AOS graph/dependency tools with
typed consumption and instance-aware views. Any new flags require CLI design;
the examples here specify information, not currently available command syntax.

Useful questions include:

- Which abilities does this exact package provide and require?
- How does this binary consume OpenSSL, and why is that output retained?
- Which nginx instance owns this virtual host, and which application supplied it?
- What manager, credentials, storage, and network policy will this service use?
- Which effects will an update perform, and which need unavailable authority?
- Which consumers prevent provider removal or retirement of an older generation?
- Why did activation commit configuration but fail to establish readiness?

An illustrative diagnostic is:

```text
Cannot activate my-app in container web:
  my-app.web consumes nginx.virtual-host ABI 1
  provider nginx/edge requires systemd.service ABI 1
  selected environment has no available or planned systemd manager
  prepare a compatible system-container environment, or select an
  application-supported foreground deployment
```

Diagnostics should name supported alternatives only when metadata establishes
that they exist. They must not suggest weakening required security settings.
Return structured errors alongside readable explanations so UIs do not parse
human text. Redact private binding details according to the reader's scope.

Previews identify changed inputs, provider replacements, reload/restart/boot
effects, required authority, external obligations, and non-reversible steps.
Removal previews traverse typed reverse dependencies. They do not equate every
retention edge with a running service or every build dependency with a runtime
consumer. A preview is a plan with stated assumptions, not a guarantee that
runtime conditions will remain unchanged.

## AOS Hub and generated reference pages

Generate interface, request, result, guarantee, and operation documentation
from the same versioned contracts used for validation. Package-authored prose
explains intent and tradeoffs. The signed release's documentation locator
continues to resolve exact reference material, including offline use.

Hub should show provided/required interfaces, how dependencies are consumed,
supported environments, configuration contributions, and declared activation
behavior. Cross-links must resolve within an explicit release/ABI context;
"latest" documentation must not explain an older bound implementation by
accident. Label examples and optional requirements clearly.

Hub's static/reference browser consumes bounded generated data and existing
release indexes. It does not evaluate arbitrary package Nix in a request path,
whether hosted natively or in a Worker. A deployment-aware view requires a
separate authenticated connection and must distinguish private deployment
state from public registry documentation.

Documentation-only prose edits have a separate identity from executable
contracts. They do not cause service restarts, configuration digest churn, or
new authority decisions. A changed semantic schema or mapping can affect
runtime identity even when its documentation happens to change alongside it.

## Editor support

The existing [documentation language server](../../../crates/aos-package/src/documentation_lsp.rs)
is the starting point for interface hover text, completion, request/result
schemas, and known compatibility diagnostics. It can identify an invalid
field or unresolved explicit provider from available authenticated metadata.

Do not execute arbitrary Nix from an editor buffer implicitly. Full evaluation
uses the existing explicit, restricted evaluation path. Static editor checks
must label what they cannot prove about conditional requirements, authorization,
or future runtime availability.

## Generation records and actual consumers

Preserve the independent package-profile, configuration, image, and per-user
generation axes documented in [upgrades](../../users/aos/upgrades.md).
Associate them through exact binding and transaction records instead of
pretending that one generation number identifies all system state.

An activation record should connect desired and committed generations, the
plan and handler identities, provider/resource assignments, and observed
consumer revisions. A service may still run an old payload after a newer
configuration generation commits and its restart fails. Report that mixed
state directly; a current profile symlink does not prove process convergence.

Generation comparison should explain semantic changes: changed provider ABI,
credential reference, enforcement guarantee, configuration contribution,
artifact, or transition strategy. Separate documentation-only differences
from runtime-affecting differences.

Garbage collection retains exact artifacts needed by active consumers,
in-progress/recoverable transactions, retained generations, and advertised
rollback windows. Preserve existing Nix references and explicit roots for
dependencies represented outside store strings. A generation record cannot
retain a live descriptor by serializing its number.

Rollback selects a retained target and constructs a new validated transition.
It checks current policy, providers, credentials, state-format compatibility,
and boot/module ABI. Historical authorization is evidence, not a grant to
revive revoked access. Where a credential version or external resource cannot
be recovered, explain the missing prerequisite before claiming rollback is
available.

## Verification and audit

Verification separates signed artifact integrity, contract validity, binding
authorization, and live enforcement observations. Each answers a different
question. Store hashes do not prove that a service started; a successful
health probe does not prove every declared isolation mechanism is enforced.

Retain useful provenance and completion evidence with bounded size and access
control. Public documentation and shared diagnostics must contain neither
secret bytes nor low-entropy secret hashes that enable guessing. Private
credential identifiers and topology may also require redaction.
