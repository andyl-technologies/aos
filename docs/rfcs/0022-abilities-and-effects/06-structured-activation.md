# Structured activation and package generations

One checked deferred graph describes a desired installation scope. The runtime
executes terminal handlers in dependency order, checks returned values, and
resolves references before dispatching consumers. Composed handlers export child
results. Logical identity stays stable across package upgrades; revisions derive
from semantic content and selected implementations.

The effect journal handles observation, update, removal, and three lifetimes.
The generation journal records retained inputs and the committed package state.
Recovery bridges the effect-completion/generation-commit boundary through a
transaction receipt. Rollback applies retained desired state as a new transaction;
pruning releases old generation roots. Journals are bounded without automatic
compaction. See the [execution contract](execution-contract.md).

Production boot, image, and installed-package orchestration must consume these
same APIs. Their migration is not implied by the infrastructure fixture passing.

See the [target state](13-target-state.md) and the
[end-to-end code examples](../../users/aos/runtime-abilities.md).
