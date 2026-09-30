# Package, image, and platform integration

The package recipe builds payload outputs and optionally retains a module
directory and explicit module dependencies. Native deployment and documentation
companions are generated from this declaration. The
[infrastructure guide](infrastructure-cutover.md) defines their wire formats and
Rust consumers; the [author guide](../../users/aos/runtime-abilities.md) shows the
packaging and execution path.

Selecting a payload output installs that output. Available sibling outputs and
module dependency packages are resolution context, not an instruction to install
all of their software. Actual effect inputs and handlers add the artifacts they
use. Generated documentation and qualification metadata do not make unused
payloads or build-only probe tools runtime dependencies.

Publication authenticates each selectable output and its exact native companion.
A named output cannot borrow another output's root measurement or signed binding.
Later evaluation may select a previously unrealized artifact only using its
original retained release proof and exact store metadata.

APM evaluates the installed module closure with immutable baseline and operator
sources, then submits a native package transaction. Install, upgrade, removal,
reconfiguration, rollback, and generation pruning use that same machinery. The
system profile is also the host boot consumer's authoritative package profile.
A subsequent boot preserves its committed operator changes and resumes pending
work before accepting new desired state.

Images retain the module library, source descriptors, package artifacts, and
handlers required for their selected scopes. Early boot supplies the primitives
needed to run the package runtime; package-owned operations describe subsequent
changes. A smaller container scope selects a package-managed base instead of
inheriting every server payload.

Alternative service, networking, storage, or sandbox implementations can expose
compatible domain options and operations. Required features remain explicit and
composable. Supporting another kernel also requires its toolchain, packages,
boot path, and process transport; replacing a handler alone does not supply them.

Current consumer integration and qualification status is tracked separately in
[the migration checklist](consumer-migration.md).
