# Statute Mounts

Mounts embed protocol handlers into the Statute key namespace. Git
repositories, workflows, and KV data are all mounts -- protocol handlers
attached to arbitrary directory paths in the unified Statute tree. The root
`/` is itself a mount. There are no built-in paths beyond `/_schema` and
`/_permissions` -- every path in the tree is user-defined through schema
declarations.

## Overview

A mount is a directory in the Statute namespace that delegates read/write
operations to a protocol handler. The handler defines how keys under that
path are resolved, validated, and stored. Mounts are defined in `_schema`
and inherit permissions from the Statute tree. Mounts can be placed at any
path -- there is no convention or requirement for specific locations.

```
/                                    <- statute mount (root)
    _schema                          <- defines mounts + schemas + capabilities
    _permissions                     <- root access control
    infra/
        config                       <- statute KV value (StoreRef)
    repos/
        my-project/                  <- git mount (user chose this path)
            refs/heads/main          <- git ref (commit meta hash)
            README.md                <- file content (ref -> commit -> tree -> blob)
            src/main.rs              <- file content
        my-project-ci/               <- workflow mount (reactive, watches deps)
            definition               <- workflow DAG with read steps
            runs/                    <- auto-managed by mount handler
                {workflow_id}/
                    status
                    steps/
    teams/
        frontend/
            ci/                      <- another workflow mount
                definition
                runs/
    tenants/
        alice/                       <- statute sub-mount (isolated namespace)
            _schema
            _permissions
```

Every path resolves through a mount handler. Reading `/infra/config` goes
through the statute mount handler (tree traversal). Reading
`/repos/my-project/README.md` goes through the git mount handler (ref ->
commit -> tree -> blob resolution). Both return a `StoreRef`. The paths
`/infra/`, `/repos/`, `/teams/` are arbitrary -- users define them in
`/_schema`.

## Mount Types

### statute

The default mount type. Keys map directly to tree/blob objects in
`objects.mdb`. Reads are tree traversals. Writes create new tree/blob
objects via copy-on-write.

| Operation | Implementation |
|---|---|
| `read(key)` | Tree traversal -> blob -> StoreRef |
| `write(key, value)` | Serialize value as blob, CoW tree update, include in block tx |
| `list(prefix)` | Return tree entries at the prefix path |
| `exists(key)` | Tree traversal, check entry exists |

### git

A git repository mount. Exposes refs, commit history, and file content
at any commit. Uses the same tree/blob/meta objects in `objects.mdb`
as the store and statute. Can be mounted at any path.

| Operation | Implementation |
|---|---|
| `read(key)` | Resolve: HEAD -> ref -> commit -> tree -> blob -> StoreRef |
| `write(ref, commit)` | Update ref (push): wrapped in a Statute block transaction |
| `list(prefix)` | List refs, or list tree entries at a commit |
| `exists(key)` | Check ref or file exists |

Reading a file path resolves through the current HEAD (or a specified ref):
1. Read HEAD -> `refs/heads/main`
2. Read ref -> commit MetaObject hash
3. Follow commit's `tree` ref -> root TreeObject
4. Traverse tree to the file path -> blob hash
5. Return StoreRef to the blob

Git pushes are Statute transactions. The mount handler validates the push
(fast-forward check, force-push authorization) and updates the ref in the
state tree.

### workflow

A reactive workflow mount. Contains a workflow definition with read
dependencies, argument keys, and an auto-managed `runs/` directory. The
mount handler watches read dependencies across blocks and creates new runs
when inputs change.

| Operation | Implementation |
|---|---|
| `read(key)` | Read step state, run status, definition, or argument -> StoreRef |
| `write(key, value)` | Write to argument key or definition; triggers re-evaluation |
| `list(prefix)` | List runs, steps, argument keys |
| `exists(key)` | Check run or argument exists |

#### Mount Internal Structure

```
{mount_path}/
    _schema                     <- { _mount: "workflow" }
    _permissions                <- who can trigger, view runs
    definition                  <- the workflow DAG (steps with read/build/run/etc.)
    {arg1}                      <- argument key (write triggers re-evaluation)
    {arg2}                      <- another argument key
    runs/                       <- auto-managed by mount handler
        {workflow_id}/
            status              <- pending | running | completed | failed | cancelled
            spec_hash           <- #StoreRef to resolved WorkflowSpec
            triggered_at        <- timestamp
            read_values         <- snapshot of all resolved read values
            transitions/
                {step_id}       <- transition record points
            steps/
                {step_id}/
                    status
                    result
```

#### Reactive Evaluation

The workflow mount handler is reactive. On every new block, it compares
the merkle hashes of its read dependencies between the previous block and
the current block. If any dependency changed, it resolves all reads against
the new block, computes a workflow ID, and (if that ID is new) creates a
run.

```
on_block(block_n):
    for each read dep in definition:
        old_hash = merkle_hash(dep_path, block[n-1])
        new_hash = merkle_hash(dep_path, block[n])
        if old_hash != new_hash:
            changed = true
    if changed:
        resolved = {}
        for each read dep in definition:
            resolved[dep] = read(dep_path, block[n])
        workflow_id = hash(definition_content, resolved)
        if runs/{workflow_id} does not exist:
            create run at runs/{workflow_id}
            announce workflow via gossipsub
```

#### Workflow ID Derivation

The workflow ID is the hash of the definition content concatenated with
the resolved read values:

```
workflow_id = blake3(
    canonical(definition),
    sorted([(dep_path, resolved_value) for dep in read_deps])
)
```

Same definition + same resolved values = same workflow ID = no new run.
Changed inputs = new workflow ID = new run. This makes workflow execution
idempotent with respect to its inputs.

#### Read Steps and Relative Paths

Read steps in the definition support both relative and absolute paths:

- `read(./key)` -- resolves relative to the mount path. Reads a mount-local
  argument key. This is how workflows accept parameters.
- `read(/absolute/path)` -- resolves against the root Statute namespace.
  Reads from any mount in the tree.

Relative paths make definitions portable -- the same definition works
regardless of where the workflow mount is placed.

#### Templates Are Unnecessary

The reactive model with mount-local argument keys replaces the template
abstraction entirely. A workflow with `read(./key)` steps is inherently
parameterized:

1. Mount the workflow at some path
2. Write values to the argument keys
3. The mount handler detects the change, resolves reads, computes a new
   workflow ID, and creates a run

There is no separate "instantiation" step. Writing to arguments IS
instantiation.

## Capabilities

Capabilities are **operation interceptors** -- middleware that processes
operations before they reach the mount handler. Capabilities are declared
per-mount in `_schema`.

### Capability Types

| Capability | Intercepts | Does | Implies |
|---|---|---|---|
| `meta` | All operations | Reserves prefixed keys (default `_`) for mount metadata. Data keys cannot use the prefix. | -- |
| `schema` | Writes | Validates values against `_schema`. Enables sub-mount definitions. | `meta` |
| `permissions` | All operations | Checks `_permissions` via Zanzibar relation traversal. | `meta` |

### Operation Flow

```
client request
  -> permissions capability (check _permissions)
  -> schema capability (validate against _schema)
  -> meta capability (reserve underscore prefix)
  -> mount handler (statute/git/workflow)
  -> objects.mdb (read/write tree/blob/meta objects)
  -> response (StoreRef)
```

### Capability Configuration

Capabilities are configurable per-mount:

```cue
_capabilities: {
    meta: {
        prefix: "_"                  // reserved key prefix (default "_")
    }
    schema: true                     // enable schema validation (implies meta)
    permissions: true                // enable access control (implies meta)
}
```

A mount with `schema` capability can define sub-mounts (via `_schema`).
A mount WITHOUT `schema` cannot -- it's a leaf mount. This provides natural
sandboxing.

### Capability as Abstraction

Capabilities are essentially filters on the operation pipeline:

```
capability "schema":
    on_write(key, value):
        schema = find_schema(key)     // walk up _schema hierarchy
        if schema:
            validate(schema, value)    // CUE validation
            if invalid: REJECT
        pass_through()

capability "permissions":
    on_any(operation, key, identity):
        perms = find_permissions(key)  // walk up _permissions hierarchy
        if perms:
            check(perms, operation, identity)  // Zanzibar relation check
            if denied: REJECT
        pass_through()

capability "meta":
    on_any(operation, key):
        if key.basename.starts_with(prefix):
            if not mount_internal_operation:
                REJECT                 // data keys can't use reserved prefix
        pass_through()
```

## Affinity

Every mount in Statute accepts an `_affinity` declaration. Affinity controls
which nodes (and which storage tiers on those nodes) pin store objects
referenced under that mount's subtree. Nodes that don't match the affinity
treat the mount's `#StoreRef` values as LRU-evictable -- they are not pinned
against GC.

### Schema

```cue
_affinity: {
    node?: { [string]: string }    // match against node labels (from [clusters.X.node.labels])
    tier?: { [string]: string }    // match against storage tier labels (from [[store.tiers]])
}
```

- If only `node` is specified: pin on matching nodes, default tier.
- If only `tier` is specified: pin on all nodes, in matching tiers.
- If both: pin on matching nodes, in matching tiers.
- If omitted or empty: inherit parent. Root default: all nodes, default tier
  (= pin everywhere, current behavior).

### Scoping (Inheritance Down the Tree)

A child's effective affinity is the intersection of its declared affinity and
its parent's effective affinity. Children can narrow (add more label
requirements) but never widen. If a parent requires
`{ node: { role: "cache" } }`, a child cannot escape that constraint -- even
an empty `_affinity` inherits the parent's.

```
/                                    effective: {} -> all nodes, all tiers
  infra/                             (inherits root) -> all nodes
    config                           #StoreRef pinned on ALL nodes
  objects/                           _affinity: { node: { role: "cache" } }
    |                                effective: { node: { role: "cache" } }
    +-- hot/                         _affinity: { tier: { media: "nvme" } }
    |                                effective: { node: { role: "cache" }, tier: { media: "nvme" } }
    |                                (narrowed: cache nodes, NVMe tier only)
    +-- cold/                        _affinity: { tier: { media: "hdd" } }
    |                                effective: { node: { role: "cache" }, tier: { media: "hdd" } }
    +-- sneaky/                      _affinity: {}  (tries to widen)
                                     effective: { node: { role: "cache" } }
                                     (constrained by parent, can't escape)
```

### Fetch-on-Pin

When a node discovers a new `#StoreRef` in Statute state that falls under a
mount whose effective affinity matches this node, it proactively fetches the
object in the background (if not already local). This replaces the separate
replication protocol -- Statute consensus distributes the state, matching
nodes retain the objects.

### Interaction with GC

The GC closure walker checks the effective affinity at each mount boundary.
If this node doesn't match, the walker skips that subtree's `#StoreRef`
pinning. See gc.md.

### Affinity Subsumes Replication

There is no separate replication protocol. The replication factor for a store
object is determined by how many nodes match its mount's effective affinity.
Want more replicas? Add nodes with matching labels, or broaden the affinity.
Want fewer? Narrow the affinity. The policy is visible in Statute (auditable,
schema-validated) and changes are Statute transactions.

## Schema Defines Mounts

Mounts are declared in `_schema` using the `_mount`, `_capabilities`, and
`_affinity` fields. Paths are user-defined -- the schema describes the
structure, but there are no built-in path conventions.

The mount definition fields are:
- `_mount`: mount type (statute, git, workflow)
- `_capabilities`: operation interceptors (meta, schema, permissions)
- `_affinity`: node/tier label selector for pin scoping

```cue
// /_schema (root mount definition)
{
    _mount: "statute"
    _capabilities: { schema: true, permissions: true }

    // User-defined path for git repositories
    repos: {
        _mount: "statute"
        _capabilities: { schema: true, permissions: true }

        [_name=string]: {
            _mount: "git"
            _capabilities: { permissions: true }
            // No schema capability -> cannot define sub-mounts inside a repo
        }

        // Workflow mounts alongside their repos
        [_name=string & =~"-ci$"]: {
            _mount: "workflow"
            _capabilities: { permissions: true }
        }
    }

    // User-defined path for team namespaces
    teams: {
        _mount: "statute"
        _capabilities: { schema: true, permissions: true }

        [_team=string]: {
            _mount: "statute"
            _capabilities: { schema: true, permissions: true }

            // Each team can define their own sub-mounts
            ci: {
                _mount: "workflow"
                _capabilities: { permissions: true }
            }
        }
    }

    // Multi-tenant statute sub-mounts
    tenants: {
        _capabilities: { schema: true, permissions: true }

        [_tenant=string]: {
            _mount: "statute"
            _capabilities: { schema: true, permissions: true }
            // Tenant defines their own _schema and _permissions
        }
    }
}
```

## Transactions Wrap Mount Operations

Every mount operation is wrapped in a Statute block transaction. The
transaction includes the mount path and the mount-specific operation:

```
MetaObject (transaction) {
    fields: [
        { key: "type",       text: "mount_tx" },
        { key: "mount",      text: "/repos/my-project" },
        { key: "mount_type", text: "git" },
        { key: "operation",  ref: <mount-specific operation MetaObject> },
        { key: "author",     text: "peer:QmAlice" },
        { key: "nonce",      integer: 42 },
        { key: "ucan",       ref: <ucan blob> },
        { key: "signature",  ref: <sig blob> },
    ]
}
```

### Statute Mount Transaction

```
MetaObject (statute write) {
    fields: [
        { key: "type",       text: "statute_write" },
        { key: "key",        text: "/infra/config" },
        { key: "value",      ref: <new value blob hash> },
        { key: "prev_value", ref: <previous value blob hash> },
    ]
}
```

### Git Mount Transaction

```
MetaObject (git push) {
    fields: [
        { key: "type",    text: "git_push" },
        { key: "ref",     text: "refs/heads/main" },
        { key: "old",     ref: <old commit meta hash> },
        { key: "new",     ref: <new commit meta hash> },
    ]
}
```

### Workflow Mount Transaction

```
MetaObject (workflow transition) {
    fields: [
        { key: "type",       text: "workflow_transition" },
        { key: "step_id",    text: "build-gcc" },
        { key: "transition", text: "completed" },
        { key: "executor",   text: "peer:QmBob" },
        { key: "result",     ref: <result store object hash> },
    ]
}
```

### Workflow Run Creation Transaction

When the workflow mount handler detects a dependency change:

```
MetaObject (workflow run creation) {
    fields: [
        { key: "type",        text: "workflow_run_create" },
        { key: "workflow_id", text: "<blake3 hash>" },
        { key: "definition",  ref: <definition store hash> },
        { key: "read_values", ref: <snapshot of resolved reads> },
        { key: "triggered_at", integer: <block timestamp> },
        { key: "trigger",     text: "/repos/my-project/refs/heads/main" },
    ]
}
```

All mount operations go through HotStuff consensus. The mount type determines
how the operation modifies the state tree, but the consensus mechanism is
uniform.

## Reading Across Mounts

Because all mounts resolve to StoreRefs in `objects.mdb`, reads work
uniformly across mount types:

```
read("/infra/config")
  -> statute mount -> tree traversal -> blob -> StoreRef

read("/repos/my-project/README.md")
  -> git mount -> HEAD -> commit -> tree -> blob -> StoreRef

read("/repos/my-project-ci/runs/{wf_id}/steps/build/result")
  -> workflow mount -> run state -> StoreRef
```

All return StoreRef. The caller does not need to know the mount type.

### Workflow `read` Step

The workflow `read` step can read from any mount. It supports both
absolute paths (reading from other mounts) and relative paths (reading
mount-local argument keys):

```
WorkflowStep {
    id: "get-commit"
    action: read {
        key: "/repos/my-project/refs/heads/main"
    }
}

WorkflowStep {
    id: "get-arg"
    action: read {
        key: "./commit"                  // relative to workflow mount path
    }
}
```

Both return StoreRef. Relative paths are resolved by the mount handler
before the workflow spec is hashed and submitted.

## Mount Nesting and Sandboxing

### Sub-Mounts Require Schema Capability

A mount can only define sub-mounts if it has the `schema` capability
(because mounts are declared in `_schema`). A mount WITHOUT `schema`
is a leaf -- it cannot create new mounts inside itself.

```
/                            <- statute, has schema -> CAN define sub-mounts
    repos/
        my-project/          <- git, NO schema -> CANNOT define sub-mounts
                                (git repos are self-contained leaves)
        my-project-ci/       <- workflow, NO schema -> self-contained leaf
                                runs/ managed internally, not via sub-mounts
    tenants/
        alice/               <- statute sub-mount, HAS schema -> CAN define sub-mounts
            _schema          <- alice defines her own schema + sub-mounts
            _permissions     <- alice controls her own access
            data/            <- alice's namespace
            ci/              <- alice can mount workflows inside her namespace
```

### Sandboxing Properties

| Mount has `schema`? | Can define sub-mounts? | Can have `_schema`? |
|---|---|---|
| Yes | Yes | Yes |
| No | No | No (reserved key blocked by `meta` capability) |

This is the sandboxing mechanism: removing `schema` capability from a mount
prevents it from creating new mounts or defining schemas inside itself. A
workflow mount without `schema` capability cannot create arbitrary sub-mounts
-- it manages only its own `runs/` directory internally.

### Statute-in-Statute (Multi-Tenancy)

A statute sub-mount creates an isolated KV namespace with its own schema
and permissions, sharing the same consensus:

```cue
// /_schema
tenants: {
    [_tenant=string]: {
        _mount: "statute"
        _capabilities: { schema: true, permissions: true }
    }
}
```

Tenant `alice` has full control over her `_schema` and `_permissions` within
`/tenants/alice/`, but cannot affect anything outside her mount. The root
`_permissions` still controls who can CREATE tenant mounts.

Within her namespace, alice can define git mounts, workflow mounts, and
nested statute sub-mounts -- the full mount system is available recursively.

## Examples

### Per-Repo CI (Reactive Workflow)

A git repository and its CI workflow mounted side-by-side:

```
/repos/
    my-project/                      <- git mount
        refs/heads/main              <- changes on push

    my-project-ci/                   <- workflow mount
        definition = {
            steps: [
                { id: "src", action: read { key: "/repos/my-project/refs/heads/main" } },
                { id: "build", action: build { drv: "...", deps: ["src"] } },
                { id: "test", action: run { image: "...", deps: ["build"] } },
                { id: "record", action: record { deps: ["test"] } }
            ]
        }
        runs/
            abc123.../               <- auto-created when main changes
                status = "completed"
                read_values = { "/repos/my-project/refs/heads/main": "commit:fa9c..." }
                steps/
                    build/
                        status = "completed"
                        result = <store ref>
```

When a developer pushes to `my-project/refs/heads/main`:
1. The push is committed in a block
2. The workflow mount handler for `my-project-ci` runs `on_block`
3. It detects the merkle hash at `/repos/my-project/refs/heads/main` changed
4. It resolves all read deps against the new block
5. It computes `workflow_id = hash(definition, resolved_reads)`
6. If `runs/{workflow_id}` does not exist, it creates the run
7. The workflow engine picks up the new run and executes it

### Parameterized Workflow (Replacing Templates)

Instead of a template that gets instantiated, use a workflow with
mount-local argument keys:

```
/deploy/
    staging/                         <- workflow mount
        definition = {
            steps: [
                { id: "image", action: read { key: "./image_ref" } },
                { id: "env", action: read { key: "./environment" } },
                { id: "deploy", action: run { deps: ["image", "env"], ... } }
            ]
        }
        image_ref                    <- argument: write a StoreRef here
        environment                  <- argument: write "staging" here
        runs/
            ...
```

To trigger a deployment:
```
write("/deploy/staging/image_ref", <new image store ref>)
```

The mount handler detects `./image_ref` changed, resolves all reads,
computes a new workflow ID, and creates a run. No template instantiation,
no separate API -- just a write.

### Per-Team Workflows

Teams define their own workflow structure within their namespace:

```
/teams/
    frontend/                        <- statute mount (has schema)
        _schema = {
            ci: { _mount: "workflow", _capabilities: { permissions: true } }
            repos: {
                [string]: { _mount: "git", _capabilities: { permissions: true } }
            }
        }
        _permissions = { ... }       <- team controls access

        repos/
            web-app/                 <- git mount
                refs/heads/main
        ci/                          <- workflow mount
            definition = {
                steps: [
                    { id: "src", action: read { key: "/teams/frontend/repos/web-app/refs/heads/main" } },
                    { id: "build", action: build { ... } },
                    { id: "deploy", action: run { ... } }
                ]
            }
            runs/
```

### Nested Workflow Triggering

One workflow's completion can trigger another via the reactive model.
The downstream workflow reads a key that the upstream workflow writes
as its final step:

```
/pipelines/
    build/                           <- workflow mount
        definition = {
            steps: [
                { id: "src", action: read { key: "/repos/app/refs/heads/main" } },
                { id: "build", action: build { ... } },
                { id: "publish", action: record { key: "/artifacts/app/latest", deps: ["build"] } }
            ]
        }

    integration-test/                <- workflow mount
        definition = {
            steps: [
                { id: "artifact", action: read { key: "/artifacts/app/latest" } },
                { id: "test", action: run { deps: ["artifact"], ... } }
            ]
        }
```

When `build` completes and writes to `/artifacts/app/latest`, the
`integration-test` mount detects the change and creates a new run.
No explicit workflow chaining -- just reactive reads on shared state.

### Multi-Tenant Sub-Mounts

Tenants get isolated statute namespaces with full mount capabilities:

```
/tenants/
    acme-corp/                       <- statute sub-mount
        _schema = {
            _mount: "statute"
            _capabilities: { schema: true, permissions: true }
            code: {
                [string]: { _mount: "git", _capabilities: { permissions: true } }
            }
            ci: {
                [string]: { _mount: "workflow", _capabilities: { permissions: true } }
            }
        }
        _permissions = { ... }       <- acme controls their own access

        code/
            api-server/              <- git mount
        ci/
            api-ci/                  <- workflow mount
```

Acme Corp defines their own paths, their own schemas, their own permissions.
They cannot see or affect other tenants or the root namespace (beyond what
root `_permissions` grants).

## Mount Registration

When the daemon processes a Statute block that contains a mount definition
(in `_schema`), it:

1. Parses the `_mount` field to determine the mount type
2. Loads the mount handler for that type (statute, git, workflow)
3. Configures capabilities (meta, schema, permissions)
4. Routes subsequent operations under that path to the handler
5. For workflow mounts: registers read dependencies for reactive evaluation

Mount handlers are compiled into the daemon -- new mount types require a
daemon update. The mount CONFIGURATION (which paths use which types) is
dynamic and defined in `_schema`.

For workflow mounts, registration additionally:
- Parses the `definition` key to extract read dependencies
- Subscribes to merkle delta notifications for each dependency path
- Performs an initial evaluation to check if any runs should exist

## The Root Mount

The root `/` is a statute mount with schema + permissions capabilities.
The genesis block initializes it:

```
Genesis:
  /_schema = { _mount: "statute", _capabilities: { schema: true, permissions: true }, ... }
  /_permissions = { relations: { root: { ... } }, rules: { ... } }
```

Everything else -- git repos, workflows, tenants, team namespaces -- is
defined as sub-mounts within this root via `_schema`. There are no built-in
paths. The root `_schema` defines whatever structure the operator wants.
Two different Statute clusters can have completely different path layouts.

## Relationship to Other Docs

- [statute.md](statute.md) -- Statute BFT consensus, values as store objects.
- [git.md](git.md) -- git mount type implementation.
- [workflow.md](workflow.md) -- workflow mount type, execution engine.
- [workflow-spec.md](workflow-spec.md) -- workflow `read` step, spec format.
- [storage.md](storage.md) -- objects.mdb shared by all mount types.
- [system.md](system.md) -- mounts as the unification layer.
