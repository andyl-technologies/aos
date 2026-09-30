# Design choices and remaining limits

## Ordinary modules instead of parallel registries

Separate maps for interfaces, implementations, consumers, requests, and docs
make authors manually reconnect facts that Nix modules already merge.
Operations instead own their input, result, handler, and effect submodules.
Domain conveniences derive from that fixed point. The serialized graph is an
output for the runtime, not another authoring interface.

## Retained module sources instead of frozen evaluated defaults

A built package retains its module directory and exact dependencies. Installation
re-evaluates these sources against the selected scope and operator configuration.
Freezing image defaults would lose recursive configuration and make package
changes depend on an unrelated build-time host configuration.

## Typed compositions instead of one activation script

A composed handler has typed children, explicit dependencies, and checked result
exports. This preserves handler selection and runtime recovery boundaries.
Backend-specific programs still implement terminal operations; the graph does
not make arbitrary shell mutations transactional or reversible.

## Semantic revisions instead of manual counters

Logical identity describes the installed resource. Semantic inputs and selected
implementation artifacts determine its revision. A routine package rebuild does
not require an author-maintained migration number. Rollback reconciles retained
desired state as a new transaction rather than rewinding execution history.

## Rich domain contracts instead of a lowest-common-denominator platform

Shared service options can include ordering, credentials, reloads, and isolation.
Multiple modules may supply compatible parts of an implementation. An unavailable
required operation fails before activation; it is not silently downgraded.

## Explicit limits

The process transport currently uses Linux facilities. Another OS needs a
matching transport, packages, and boot path as well as compatible handlers.
Journals are bounded and have no automatic compaction. Handler observation must
resolve uncertain mutations; the runtime cannot guarantee that every external
system admits safe retries. Static documentation shows only the selected fixed
point, while observed runtime state needs separate inspection.

Unexecuted qualification remains unqualified. Implementation checks and
qualification limits are tracked in [the migration status](consumer-migration.md); neither follows from
this design's expressiveness alone.
