# 26 — Surfaces

This file owns the one abstraction through which a tree is ever shown to
anything outside the store: the **surface**. A FUSE mount, an EROFS image, a
block device, a virtiofs export, the Nix binary cache protocol, the Remote
Execution API, the OCI Distribution API, git upload-pack, an HTTP browser,
and the Terrane wire API are all surfaces. A running instance is nothing more
than a list of **exposures**, each one a view shown through a surface at an
endpoint. This file defines the surface interface, the view selector, the
exposure record, schema validation, the write path, credential mapping, the
plugin model, and the configuration grammar. Individual surfaces are
specified in [`27-surface-fuse.md`](27-surface-fuse.md) through
[`30-surface-protocols.md`](30-surface-protocols.md) and registered in
[`reference/surface-registry.md`](reference/surface-registry.md).

## Model

Three things describe how a tree is shown:

```text
view      what is shown:   a ref or commit, optionally a subtree, plus policy
surface   how it is shown: a kernel interface or a protocol
endpoint  where:           a mount path, a socket, a URL prefix, a device node
```

A view answers "which tree, at which commit, under which trust and rules". A
surface answers "through which interface". An endpoint answers "at which
address". The three are orthogonal: the same view may be exposed through
several surfaces at once, and one surface implementation serves any view
whose root satisfies its schema.

A surface has no privileged access. It reads and writes trees only through
the repository layer described in
[`03-architecture-overview.md`](03-architecture-overview.md), so it inherits
authorization ([`22-authentication-and-authorization.md`](22-authentication-and-authorization.md)),
trust filtering ([`23-provenance-and-trust.md`](23-provenance-and-trust.md)),
tiering ([`19-tiering-and-topology.md`](19-tiering-and-topology.md)), and
consistency modes ([`20-consistency.md`](20-consistency.md)) without
implementing any of them. This is what makes a surface small: a protocol
surface is a mapping between a foreign protocol's verbs and repository verbs,
and a realizer is a mapping between kernel requests and repository reads.

The set of surfaces is closed at build time. A surface compiled into an
instance is registered by name; a surface that is not compiled in is
unavailable, and the configuration that names it is rejected. Third parties
who need a new way to show a tree do not need a plugin interface: the wire
protocol is the full repository API, so an ordinary client process holding a
token is a surface running out of process.

## The surface interface

- **[SURF-1]** A surface MUST implement exactly the following interface, and
  an implementation MUST NOT expose any additional entry point that a surface
  can call to bypass the repository layer. *Gate:* `gate:surface-interface`.

```text
trait Surface {
    /// The tree layout and attribute set this surface requires of a view's
    /// root. Evaluated at configuration time against the view's root.
    fn schema(&self) -> TreeSchema;

    /// Begin serving `view` at `endpoint`. Returns a handle that reports
    /// status and can be drained and stopped.
    fn serve(&self, view: View, endpoint: Endpoint) -> Result<Serving, Error>;
}

trait Serving {
    fn status(&self) -> ExposureStatus;
    fn drain(&self, deadline: Duration) -> Result<(), Error>;
    fn stop(&self) -> Result<(), Error>;
}
```

- **[SURF-2]** A surface MUST read tree content, entries, objects, and refs
  only through the repository interface. A surface MUST NOT hold a reference
  to a store, a backend, a pack, or a bucket. *Gate:* `gate:surface-interface`.
- **[SURF-3]** A surface MUST NOT hold credentials for any store. Requests a
  surface makes to the repository carry the token of the exposure or the
  token derived from the foreign protocol's credential (§ credential
  mapping), never an instance-level credential.
- **[SURF-4]** A surface MAY declare that it is **writable**. A surface that
  does not declare itself writable MUST reject every mutating request from
  its consumers with the surface's native read-only error.
- **[SURF-5]** A surface MUST tolerate the repository returning a stale ref
  value bounded by the view's consistency mode
  ([`20-consistency.md`](20-consistency.md)) and MUST NOT cache a ref value
  longer than that bound.

### The view selector

A view is written as a selector string with the following grammar:

```text
view      = target [ ":" subtree ] [ "@" policy ]
target    = ref | commit
ref       = "refs/" 1*( path-segment "/" ) path-segment
commit    = "commit:" hex
subtree   = "/" *( path-segment "/" ) [ path-segment ]
policy    = policy-name
```

Examples:

```text
refs/heads/main
refs/heads/main:/bazel
refs/tags/release-2026-09-01:/nix/store
commit:5f0a…e3:/oci
refs/heads/main@strict-trust
```

- **[SURF-6]** A view whose target is a ref MUST resolve the ref through the
  repository at the time of each read according to the exposure's reader mode
  ([`20-consistency.md`](20-consistency.md) `pinned` or `follow`). A view
  whose target is a commit MUST NOT resolve any ref.
- **[SURF-7]** A view with a `subtree` MUST present the named subtree as the
  root of what the surface shows. Paths outside the subtree MUST be invisible
  to the surface's consumers, including through `..` traversal, symlink
  targets, and hard-link identities. A subtree that does not exist in the
  resolved tree is a configuration error at exposure start and a status
  fault thereafter.
- **[SURF-8]** A `policy` name MUST refer to a policy object registered with
  the instance: a set of trust selectors
  ([`23-provenance-and-trust.md`](23-provenance-and-trust.md)), a ruleset
  ([`31-routing-rulesets.md`](31-routing-rulesets.md)), and realization
  hints. An unknown policy name is a configuration error.

### The exposure record

An exposure is the unit of configuration and of runtime status.

```text
Exposure {
    id:        stable identifier, unique within the instance
    view:      View selector
    surface:   registered surface name
    endpoint:  Endpoint (kind-specific)
    mode:      reader mode and, for writable surfaces, writer mode (20)
    token:     the capability token the surface acts under (22)
    options:   surface-specific table
}
```

- **[SURF-9]** An exposure MUST name a surface registered in
  [`reference/surface-registry.md`](reference/surface-registry.md) and
  compiled into the instance. Any other name MUST be rejected at
  configuration load.
- **[SURF-10]** An exposure's `endpoint` MUST be of a kind the surface
  accepts. The registry lists accepted endpoint kinds per surface.
- **[SURF-11]** Two exposures MUST NOT share an endpoint. A mount path, a
  socket path, a `(listen address, URL prefix)` pair, and a device node are
  each exclusive.
- **[SURF-12]** An exposure's `token` MUST carry at least `read` on the
  view's target. A writable exposure MUST carry `commit` on the target ref.
  An exposure whose token is insufficient MUST be refused at start, not at
  first request.

### Schema validation

Every surface declares the tree layout it needs. The Nix binary cache surface
requires store-path entries carrying narinfo attributes beneath one root; the
REAPI surface requires `cas/` and `ac/` directories; the browse surface
requires nothing. Declaring the schema makes a surface honest about what it
assumes and lets misconfiguration fail before any consumer connects.

```text
TreeSchema {
    required_entries:    list of (path pattern, entry kind)
    required_attributes: list of (path pattern, attribute name, type)
    required_properties: list of (property name, allowed values)
    forbidden_entries:   list of path patterns
}
```

- **[SURF-13]** At exposure start, and again whenever a `follow`-mode view's
  ref advances, the instance MUST evaluate the surface's schema against the
  view's resolved root. A root that fails validation MUST cause the exposure
  to refuse to start, or, once started, to enter a `SchemaFault` status and
  keep serving the last valid commit. *Gate:* `gate:surface-schema`.
- **[SURF-14]** Schema evaluation MUST be performed against the tree's
  metadata only and MUST NOT fetch object content.
- **[SURF-15]** A surface's schema MUST be published in the surface registry
  as a normative table, and an implementation's `schema()` MUST return a
  value equivalent to it.

### The write path

A writable surface accepts mutations in its own protocol and turns them into
commits. There is exactly one commit path in a Terrane instance, defined in
[`09-refs-and-commits.md`](09-refs-and-commits.md) and
[`20-consistency.md`](20-consistency.md); surfaces use it and never
reimplement it.

- **[SURF-16]** A writable surface MUST translate every mutating request into
  tree operations ([`07-tree-algebra.md`](07-tree-algebra.md)) applied to a
  private working tree, and MUST commit through the repository's commit
  operation. A surface MUST NOT write packs, indexes, or refs directly.
  *Gate:* `gate:surface-commit-path`.
- **[SURF-17]** A writable surface MUST honor the exposure's writer mode
  (`manual`, `periodic`, `sync`). A protocol whose semantics imply durability
  on return (for example a cache upload that returns success) MUST be
  configured with `sync` or MUST document in the registry that success means
  "accepted into the working tree" rather than "committed".
- **[SURF-18]** A surface MUST NOT commit content the exposure's token cannot
  read back. This prevents a writable surface from being used as a blind
  drop into a root the writer cannot inspect.
- **[SURF-19]** When a commit fails, a writable surface MUST return the
  failure through its own protocol's nearest error and MUST NOT acknowledge
  the mutation. The mapping to POSIX errors for realizers is normative in
  [`reference/errno-mapping.md`](reference/errno-mapping.md).

### Credential mapping

Foreign protocols carry their own credentials: a netrc password for a Nix
cache, an authorization header for REAPI, a job token for a CI cache, HTTP
basic or bearer credentials for git. Each of these is mapped to a Terrane
capability token at the surface boundary and then forgotten.

- **[SURF-20]** A protocol surface MUST map each incoming request's
  credential to a capability token before invoking the repository and MUST
  use only that token for the request. The foreign credential MUST NOT be
  retained past the request, logged, or forwarded.
- **[SURF-21]** The mapping MUST be one of: (a) the credential *is* a Terrane
  token in the protocol's transport encoding; (b) the credential is exchanged
  with a configured issuer for a Terrane token; or (c) the credential selects
  a pre-attenuated token from the exposure's configuration. An exposure MUST
  declare which mapping it uses.
- **[SURF-22]** A token obtained by mapping MUST be an attenuation of the
  exposure's token or independently valid; a surface MUST NOT escalate a
  request beyond what the exposure's own token permits.
- **[SURF-23]** A request that carries no credential MUST be evaluated under
  the exposure's `anonymous` token if one is configured and MUST be rejected
  otherwise.

### Plugins

- **[SURF-24]** In-process surfaces MUST be registered at build time by name.
  An instance MUST NOT load surface code at runtime from configuration, from
  a tree, or from a network location.
- **[SURF-25]** An out-of-process surface is any client of the wire protocol
  ([`18-protocol.md`](18-protocol.md)). It requires no interface beyond that
  protocol and runs with only the authority of its token. An implementation
  MUST NOT offer an out-of-process surface any capability that an in-process
  surface does not also obtain through the repository interface.
- **[SURF-26]** Every surface registered in this specification SHOULD be
  implementable out of process. An in-process surface MUST NOT depend on
  private hooks that an out-of-process implementation could not reproduce
  through the wire protocol, with the sole exception of realizers, which
  need local descriptor passing to a mount broker.

### Status

- **[SURF-27]** An exposure MUST report status containing: the resolved
  commit currently served; the surface name; for realizers, the realizer
  actually chosen when the configuration allowed a choice; the list of
  requested features that were degraded or unavailable and why; the writer
  and reader modes in effect; the last commit outcome; and schema validation
  state. *Gate:* `gate:surface-status`.
- **[SURF-28]** A view's identity MUST NOT include the surface or realizer
  through which it is shown. Two exposures of the same view through different
  surfaces MUST report the same served commit.

## Configuration grammar

An instance's exposures are configured as a list of `[[expose]]` tables.
The grammar is given in TOML; an implementation MAY accept an equivalent
encoding but MUST accept this one.

```toml
[[expose]]
id      = "main-nix"
view    = "refs/heads/main"
surface = "nix-cache"
at      = "https://cache.example/nix"
token   = "file:/etc/terrane/tokens/nix-cache"
mode    = { reader = "follow" }

[expose.options]
priority   = 40
compression = "zstd"

[[expose]]
id      = "main-reapi"
view    = "refs/heads/main:/bazel"
surface = "reapi"
at      = "grpc://0.0.0.0:8980"
token   = "file:/etc/terrane/tokens/reapi"
mode    = { reader = "follow", writer = "sync" }

[[expose]]
id      = "pr-1234"
view    = "refs/heads/pr/1234"
surface = "fuse"
at      = "/run/terrane/pr-1234"
token   = "file:/run/terrane/tokens/pr-1234"
mode    = { reader = "pinned", writer = "manual" }

[expose.options]
upper      = "private-cow"
passthrough = "auto"
quota_bytes = 21474836480

[[expose]]
id      = "browse"
view    = "refs/heads/main"
surface = "browse"
at      = "https://cache.example/"
token   = "anonymous:refs/heads/main:read"
```

- **[SURF-29]** The keys `id`, `view`, `surface`, `at`, and `token` MUST be
  present in every exposure. `mode` defaults to `{ reader = "pinned" }` for
  commit targets and `{ reader = "follow" }` for ref targets, with `writer =
  "manual"` for writable surfaces. `options` is surface-specific and its
  schema is given in the surface's file.
- **[SURF-30]** The `token` value MUST be a reference (a file path, a secret
  store locator, or an `anonymous:` grant literal) and MUST NOT be an inline
  token. Configuration files are not credential stores.
- **[SURF-31]** An exposure's `view` field MUST parse under the selector
  grammar above. An implementation MUST reject the configuration on any parse
  failure rather than serving a partial list.
- **[SURF-32]** Exposures MUST start in configuration order and an
  implementation MUST NOT start any exposure until every exposure has passed
  parsing, registry lookup, token sufficiency, and schema validation. A
  configuration is accepted whole or rejected whole.

## Interactions

- [`03-architecture-overview.md`](03-architecture-overview.md): surfaces are
  the top layer and reach only the repository layer beneath them.
- [`09-refs-and-commits.md`](09-refs-and-commits.md) and
  [`20-consistency.md`](20-consistency.md): writable surfaces use the single
  commit path and the writer and reader modes.
- [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md):
  exposure tokens and credential mapping.
- [`23-provenance-and-trust.md`](23-provenance-and-trust.md): policy names
  carry trust selectors.
- [`31-routing-rulesets.md`](31-routing-rulesets.md): policy names carry
  rulesets applied at realization.
- [`34-observability.md`](34-observability.md): exposure status is a
  first-class observable.
- [`reference/surface-registry.md`](reference/surface-registry.md): the
  closed set of surface names, schemas, and endpoint kinds.

## Informative: why one abstraction

Earlier designs of similar systems grew a "facade layer" for protocols, a
"CSI driver" for mounts, and a separate "gateway" for humans, each with its
own authorization path and its own bugs. Collapsing them into one interface
with one entry point into the repository means authorization, trust, and
consistency are enforced in one place and every new way of showing a tree is
a few hundred lines of mapping. See [`39-decision-register.md`](39-decision-register.md)
for the decision and the alternatives that were weighed.
