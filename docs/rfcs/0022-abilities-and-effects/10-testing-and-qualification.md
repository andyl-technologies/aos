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

A retained scenario may select a test wrapper that delegates to the real handler
and controls when its response returns. Such evidence identifies the wrapper,
backend, and scenario graph explicitly. It qualifies that composition, not the
unwrapped baseline handler's exact bytes. Production handlers do not acquire
test-only fault controls.

Required semantic coverage is explicit. An empty domain selection or a missing
required operation fails instead of producing vacuous success. Evidence for a
selected operation must cover every applicable cell in that cohort's closed
specification. Combining reports cannot invent coverage for an unexecuted cell.

The authored scenario policy also constrains meaningful actions. An empty
`required_actions` list permits both actions. Restoring retained state applies
the selected configuration; orphan retention and explicit retirement remove the
desired source. The opposite action remains in the matrix inventory with an
explicit inapplicability reason. Missing implementation support is not such a
reason. Retaining a persistent orphan produces no removal dispatch: its evidence
binds the original application receipt, unchanged live state, and the new
committed desired graph.

A future operation such as image rollout need not be enabled during initial
boot. Its scenario source is retained and evaluated against the authenticated
candidate's module library and package context before the test applies it.
The cohort binds both its adopted baseline and its selected target evaluation
with independent source commitments and digests. The fixture imports the baseline
first; it does not apply the target graph before the test starts. This separates
boot adoption from the desired state being tested while preserving exact
artifact and source identities.

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
