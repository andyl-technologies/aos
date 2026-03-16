# Workflow Templates

Workflow templates are parameterized CUE definitions stored in Statute that
produce concrete `WorkflowSpec` values when unified with parameters. Templates
live in a nested directory structure under `/workflows/templates/`, with
inherited permissions and composable template hierarchies using CUE unification.

## Overview

A template is a CUE value with two parts:

- **Parameter schema** — typed inputs with constraints and defaults
- **Spec generator** — a workflow DAG that references the parameters

CUE unification produces the concrete `WorkflowSpec`: the client reads the
template from Statute, provides parameter values, and CUE evaluation resolves
all parameters, expands list comprehensions, evaluates conditionals, and
produces a fully concrete workflow spec. This happens **client-side** — no
server-side CUE evaluation beyond schema validation of the template itself.

## Directory Structure

Templates use a nested directory structure for organization, permission
inheritance, and template composition:

```
/workflows/templates/
    _schema                          → schema for template values
    _permissions                     → root template permissions

    ci/
        _schema                      → schema for CI templates (inherits root)
        _permissions                 → who can create/modify CI templates
        base/
            template                 → base CI template (shared foundation)
        build-and-test/
            template                 → extends ci/base with test steps
        full-pipeline/
            template                 → extends ci/build-and-test with deploy

    infra/
        _permissions                 → who can modify infra templates
        deploy-service/
            template                 → service deployment template
        scale-cluster/
            template                 → cluster scaling template

    toolchain/
        _permissions                 → toolchain template permissions
        gcc/
            template                 → GCC build template
        llvm/
            template                 → LLVM build template
        full/
            template                 → extends gcc + llvm + rust
```

### Permission Inheritance

Permissions cascade down the directory tree (same as all Statute keys):

- `/workflows/templates/_permissions` → controls all templates
- `/workflows/templates/ci/_permissions` → controls CI templates (inherits root)
- `/workflows/templates/ci/full-pipeline/_permissions` → controls this specific template

A CI engineer with write access to `/workflows/templates/ci/` can create and
modify CI templates but not infra templates. An ops admin with access to
`/workflows/templates/infra/` can manage deployment templates. The root
permission controls who can create top-level template categories.

### Schema Inheritance

Schemas cascade with CUE unification (inherits = tighten constraints):

```cue
// /workflows/templates/_schema (root — all templates must satisfy this)
_inherit: "default"
{
    [string]: {
        template:     _              // CUE expression
        description:  string
        version:      uint & >=1
        author:       =~"^peer:Qm"
        created_at:   int
        tags?:        [...string]
    }
}

// /workflows/templates/ci/_schema (CI templates must also have these fields)
{
    [string]: {
        template: {
            params: {
                repo:   string       // CI templates always need a repo
                commit: string       // and a commit
                ...                  // allow additional params
            }
            ...
        }
    }
}
```

A CI template must satisfy BOTH the root schema (has description, version,
author) AND the CI schema (params include repo and commit). CUE unification
enforces this automatically.

## Template Definition

### Structure

Each template is a Statute key at `.../template` containing a CUE value:

```cue
// /workflows/templates/ci/build-and-test/template
{
    params: {
        repo:        string & =~"^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$"
        commit:      string & =~"^[a-f0-9]{40}$"
        targets:     [...string] | *["x86_64-linux"]
        run_tests:   bool | *true
        timeout:     string | *"2h"
    }

    spec: {
        nonce:    params.commit
        deadline: _                  // filled at instantiation

        steps: [
            {
                id: "fetch-source"
                action: fetch: {
                    output_hash: _   // filled by client (nix-instantiate)
                    urls: [
                        "https://github.com/\(params.repo)/archive/\(params.commit).tar.gz",
                    ]
                    hash: _          // filled by client (from flake.lock)
                }
                deps: []
            },

            for _, target in params.targets {
                {
                    id: "build-\(target)"
                    action: build: {
                        drv_hash:    _
                        output_hash: _
                    }
                    deps: ["fetch-source"]
                    timeout: params.timeout
                }
            },

            if params.run_tests {
                {
                    id: "test"
                    action: run: {
                        spec_hash: _
                    }
                    deps: [for _, t in params.targets {"build-\(t)"}]
                    timeout: "30m"
                }
            },
        ]
    }
}
```

### Placeholder Values

Templates use CUE's `_` (top/unconstrained) for values that the client must
fill in during instantiation. These are typically store hashes computed by
`nix-instantiate` or looked up from `flake.lock`. The template defines the
STRUCTURE; the client fills in the HASHES.

## Template Composition (Templates of Templates)

CUE's embedding and unification operators enable template inheritance. A
child template can extend a parent by embedding it and adding/overriding
fields.

### Base Template

```cue
// /workflows/templates/ci/base/template
#CIBase: {
    params: {
        repo:    string
        commit:  string
        targets: [...string] | *["x86_64-linux"]
    }

    spec: {
        nonce:    params.commit
        deadline: _

        _fetch_steps: [
            {
                id: "fetch-source"
                action: fetch: {
                    output_hash: _
                    urls: ["https://github.com/\(params.repo)/archive/\(params.commit).tar.gz"]
                    hash: _
                }
                deps: []
            },
        ]

        _build_steps: [
            for _, target in params.targets {
                {
                    id: "build-\(target)"
                    action: build: {
                        drv_hash: _
                        output_hash: _
                    }
                    deps: ["fetch-source"]
                }
            },
        ]

        steps: _fetch_steps + _build_steps
    }
}
```

### Extended Template (adds testing)

```cue
// /workflows/templates/ci/build-and-test/template
import "/workflows/templates/ci/base/template"

#CIBase & {
    params: {
        run_tests: bool | *true
        test_timeout: string | *"30m"
    }

    spec: {
        _test_steps: [
            if params.run_tests {
                {
                    id: "test"
                    action: run: {
                        spec_hash: _
                    }
                    deps: [for _, t in params.targets {"build-\(t)"}]
                    timeout: params.test_timeout
                }
            },
        ]

        steps: _fetch_steps + _build_steps + _test_steps
    }
}
```

### Full Pipeline (adds deploy)

```cue
// /workflows/templates/ci/full-pipeline/template
import "/workflows/templates/ci/build-and-test/template"

#CIBuildAndTest & {
    params: {
        deploy:       bool | *false
        deploy_env:   "staging" | "production" | *"staging"
    }

    spec: {
        _deploy_steps: [
            if params.deploy {
                {
                    id: "deploy-\(params.deploy_env)"
                    action: run: {
                        spec_hash: _
                    }
                    deps: if params.run_tests {["test"]}
                          else {[for _, t in params.targets {"build-\(t)"}]}
                }
            },
        ]

        steps: _fetch_steps + _build_steps + _test_steps + _deploy_steps
    }
}
```

### Composition Properties

CUE unification guarantees:

- **Child cannot weaken parent constraints.** If the base template requires
  `repo: string`, the child cannot change it to `repo?: string` (optional).
  CUE unification only tightens.
- **Child can add fields.** The build-and-test template adds `run_tests` and
  `test_timeout` parameters. The base template's params are preserved.
- **Step lists compose.** Using `_fetch_steps + _build_steps + _test_steps`,
  each template tier adds its steps. The final `steps` field is the
  concatenation.
- **Static verification.** When a template is updated in Statute, CUE
  validates that the updated template is still a valid extension of its
  parent. Invalid compositions (e.g., conflicting constraints) are rejected
  before consensus.

## Instantiation

### CLI

```bash
# Simple: template name + params
aos workflow run --template ci/build-and-test \
  --param repo=andyl/andyl-os \
  --param commit=$(git rev-parse HEAD) \
  --param targets='["x86_64-linux","aarch64-linux"]' \
  --param run_tests=true

# From a params file
aos workflow run --template ci/full-pipeline \
  --params-file ci-params.cue
```

### Internal Flow

1. **Read template.** Client reads `/workflows/templates/ci/build-and-test/template`
   from Statute via `/aos/statute/read/1.0.0`.

2. **Resolve inheritance.** If the template imports a parent (e.g., `ci/base`),
   the client reads that too. CUE unification composes them.

3. **Unify with params.** Client evaluates:
   `resolved_template & {params: {repo: "...", commit: "...", ...}}`

4. **Fill placeholders.** Client runs `nix-instantiate` to compute actual
   .drv and output hashes. Fills in all `_` placeholders in the spec.

5. **Validate.** Client runs CUE validation on the concrete spec against
   the workflow spec schema. Catches errors before submission.

6. **Store.** Client stores the concrete `WorkflowSpec` as a store object
   (`workflow.json`).

7. **Record instance.** Client writes to Statute:
   ```
   /workflows/instances/{workflow_id}/ = {
       template: "ci/build-and-test"
       params: { repo: "...", commit: "...", ... }
       spec_hash: #StoreRef
       status: "running"
   }
   ```

8. **Submit.** Client calls `/aos/workflow/run/1.0.0`.

### Static Verification on Template Update

When a template author updates a template in Statute, the Statute validation
pipeline verifies:

1. **Schema compliance.** The template value matches
   `/workflows/templates/_schema` (and inherited schemas).
2. **CUE validity.** The template is syntactically valid CUE.
3. **Parent compatibility.** If the template imports a parent, the
   composition (parent & child) must unify without errors. CUE's type
   system catches conflicts statically.
4. **Existing instances.** The Statute validator can optionally check: are
   there running workflow instances using this template? If so, warn (but
   don't block — running instances reference the spec by store hash, not
   the template).

## Template Metadata

Each template directory can have metadata alongside the `template` key:

```
/workflows/templates/ci/build-and-test/
    template                         → the CUE template definition
    description                      → "Build all targets and run tests"
    version                          → 3
    author                           → "peer:QmAlice"
    created_at                       → 1710288000
    tags                             → ["ci", "build", "test"]
    changelog                        → "v3: added aarch64 support"
```

### Listing Templates

```bash
# List all templates
aos workflow templates list

# List CI templates
aos workflow templates list ci/

# Show template details
aos workflow templates show ci/build-and-test

# Show template params (schema)
aos workflow templates params ci/build-and-test
```

These map to Statute reads at `/workflows/templates/`.

## Instance Tracking

Running and completed workflow instances are tracked in Statute, linking back
to the template and parameters used:

```cue
// /workflows/instances/{workflow_id}
{
    template:     string             // template path (e.g., "ci/build-and-test")
    params:       _                  // actual parameter values used
    spec_hash:    #StoreRef          // store hash of the concrete WorkflowSpec (auto-pinned)
    status:       "running" | "completed" | "failed" | "cancelled" | "expired"
    started_at:   int
    completed_at?: int
}
```

Queries:
```bash
# Show all instances of a template
aos workflow instances --template ci/build-and-test

# Show all instances for a repo
aos workflow instances --param repo=andyl/andyl-os

# Show instance details
aos workflow instances show {workflow_id}

# Re-run with same params
aos workflow rerun {workflow_id}
```

The `rerun` command reads the instance's params and template, re-evaluates
(in case the template has been updated), and submits a new workflow.

## CUE Import Mechanism

CUE templates reference parent templates via Statute paths:

```cue
// In /workflows/templates/ci/build-and-test/template
import "/workflows/templates/ci/base/template"
```

The client resolves imports by reading the referenced template from Statute.
This is a client-side operation — the Statute validator doesn't follow
imports (it validates each template key independently). The client is
responsible for:

1. Reading all imported templates from Statute
2. Composing them via CUE unification
3. Validating the composition is consistent
4. Producing the concrete spec

This keeps the Statute validator simple (validates individual keys against
schemas) while giving clients full CUE composition power.

## Relationship to Other Docs

- [workflow.md](workflow.md) -- workflow execution model, step types,
  claiming modes.
- [workflow-spec.md](workflow-spec.md) -- step type definitions, idempotency,
  GC pinning.
- [workflow-validation.md](workflow-validation.md) -- validation rules for
  concrete WorkflowSpec values.
- [statute.md](statute.md) -- Statute KV store where templates and instances
  are stored. CUE schema validation, permission inheritance.
- [system.md](system.md) -- workflows as one of the four building blocks.
