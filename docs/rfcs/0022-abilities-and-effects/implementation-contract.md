# Native infrastructure implementation contract

The [target state](13-target-state.md) is normative. This page maps responsibilities
to their current owners; the [guide](../../users/aos/runtime-abilities.md) contains
the shared examples rather than another set of declarations.

| Responsibility | Implementation |
| --- | --- |
| Ordinary option merging and deferred module types | `lib/modules.nix` |
| Native operation/effect and handler submodules | `lib/effects/module.nix`, `lib/effects/execution.nix` |
| Fixed-point operation reference | `lib/effects/documentation.nix` |
| Package recipe module retention and artifact companions | `lib/build/package-modules.nix`, package builder integration |
| Package-scope evaluation and documentation envelope | `lib/packages/evaluate.nix` |
| Portable graph validation | `aos-ability-plan::module_graph` |
| Effect state machine and typed results | `aos-ability-runtime::activation` |
| Module resolution and restricted Nix evaluation | `aos-package::deployment::evaluation` |
| Original store identities and private source read views | `aos-package::deployment::source_views` |
| Process dispatch and artifact admission | `aos-package::deployment::{handler,process,retention}` |
| Durable generations and recovery | `aos-package::deployment::transaction` |
| Native reference and graph rendering | `aos-doc-model::runtime` |
| Local artifact documentation | `aos docs runtime` |
| Read-only Hub artifact inspection | `aos-hub-core::web::runtime_documentation` |

No layer may introduce package-specific OS lowering into the generic library,
copy a schema into a documentation table, or reimplement graph semantics in a
presentation client. Build, publication, deployment evaluation, and runtime
execution remain distinct phases. The caller owns release authentication and
profile publication; the generation journal owns the committed transaction.

[Consumer migration](consumer-migration.md) records implementation checks and
qualification limits. The source-built `checks.effects`
fixture and `package_deployment_check` example exercise the new path independently.
