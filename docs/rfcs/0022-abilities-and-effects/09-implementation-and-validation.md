# Implementation boundaries and validation

The [implementation contract](implementation-contract.md) assigns each boundary
to its current owner. The [migration checklist](consumer-migration.md) records
remaining work. This chapter describes how to assess changes without making
whole-system claims from isolated unit tests.

1. Validate module merging, recursive defaults, provenance, missing handlers,
   deferred result compatibility, and graph composition with small pure inputs.
2. Exercise actual package envelopes and selected outputs, source-only module
   dependencies, generated references, and independently authenticated publication.
3. Compile consumer changes with Cargo through `aos-dev`, then run focused Rust
   and handler tests for the affected semantics.
4. Use source-built checks with the shared development cache to exercise actual
   Nix evaluation, package transactions, materialization, and garbage collection.
5. Evaluate complete selected host and initrd graphs with a bounded time budget.
   Compare image construction with replay of retained sources; node counts alone
   do not prove equivalent inputs or handlers.
6. Run applicable boot and domain acceptance tests against the actual selected
   image and handlers. Report unexecuted VM and physical-transition qualification
   separately from passing compilation, schema, and source-built checks.

Tests should exercise independent behavior: an actual service observation,
filesystem result, retained source replay after GC, or authenticated output
binding. Comparing two manually duplicated catalogs is not evidence of a single
source of truth. Qualification uses the production handler and exact selected
artifact context, with test inputs retained as explicit scenario sources.

Ordinary journal reads do not create, repair, or truncate state. Recovery tests
must distinguish a read-only snapshot from a mutating controller. Generation
pruning and persistent-effect retirement also have different responsibilities:
pruning releases generation roots; retirement releases a retained resource.

New work should replace its obsolete caller and remove dead code in the same
cutover. Keep OS domain definitions in their owning packages, use shared model
readers in presentation clients, and avoid broad rebuilds until focused feedback
has identified the relevant boundary.
