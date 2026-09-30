# Testing and qualification

Qualification is a claim about exact software and an exercised environment.
A declaration, generated graph, successful compilation, or handler unit test
alone does not establish that claim. The
[maintainer qualification guide](../../maintainers/qualification.md) describes
release operations; [migration status](consumer-migration.md) identifies current
integration work.

Native qualification selects concrete operations from the graph produced by
an actual candidate and its retained scenario configuration. Each cohort binds
its own matrix, source context, handlers, and effect identities. Different
cohorts may exercise the same logical operation under different configurations;
their evidence must retain those distinct contexts.

Required semantic coverage is explicit. An empty domain selection or a missing
required operation fails instead of producing vacuous success. Evidence for a
selected operation must cover every applicable cell in that cohort's closed
specification. Combining reports cannot invent coverage for an unexecuted cell.

A future operation such as image rollout need not be enabled during initial
boot. Its scenario source is retained and evaluated against the authenticated
candidate's module library and package context before the test applies it.
This separates the boot baseline from the desired state being tested without
relaxing artifact or source identity checks.

Observations must come from the domain: service-manager state, account records,
filesystem contents, network behavior, cluster state, or actual image identity.
The activation journal adds ordering, ownership, and durable result evidence;
it is not an independent oracle for the external mutation it records.

Dispatch-started evidence establishes an attempted dispatch boundary. A later
manager failure does not by itself prove that a particular handler instruction
ran. Negative cases preserve pending and indeterminate state. Cases that would
contaminate later observations run in separate disposable guests, while their
results remain part of the same required cohort coverage.

VM boot and physical image-transition checks must be reported explicitly.
Source-tree test success cannot qualify different release artifacts, and a
schema-valid imported report is not automatically trusted execution evidence.
