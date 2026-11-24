# Crucible Reference

The reference is the exhaustive catalog of the shipped `crucible` command-line
interface and canonical scenario TOML. Use the task-oriented guides for worked
procedures and the pages below to look up exact option names, accepted values,
defaults, required fields, and nested `kind` tables.

| Page | Contents |
| --- | --- |
| [Command-line reference](reference-cli.md) | Global options, every command and subcommand, terminal and save-boundary values, output formats, and exit status. |
| [Scenario and world reference](reference-world.md) | The canonical scenario document: `[scenario]`, `[world]` nodes, I/O devices, links, and node fault capabilities. |
| [Plan and property reference](reference-plan.md) | `[plan]` events, signals, bindings, opportunity operations, target selectors, the effect registry, and `[properties]` predicates. |

Read [Support boundaries](support.md) before inferring packaged operator support
from a schema or public Rust type. The [guide map](README.md#guide-map) routes
from each workflow to this catalog.

The Rust types and Clap declarations are the implementation source of truth.
Unknown TOML fields and unknown closed-vocabulary values are rejected. Generate a
scenario through the Rust builder and `to_canonical_toml` whenever possible; its
content-addressed IDs are computed values, not labels to invent by hand. See the
[scenario authoring guide](scenarios.md) and the
[representative-scenario quickstart](quickstart.md). For a conceptual walkthrough of causes,
bindings, opportunities, and effects, start with
[Signal-driven faults](signal-driven-faults.md).

Direct implementation references:

- [Clap command and option declarations](../../../crates/crucible/crucible-cli/src/main.rs)
- [Canonical TOML schema and conversions](../../../crates/crucible/crucible-engine/src/model/toml.rs)
- [Signal-driven effect registry](../../../crates/crucible/crucible-engine/src/model/fault_signal/effect_registry.rs)
- [Properties and predicate types](../../../crates/crucible/crucible-engine/src/model/plan_properties.rs)

## Value conventions

| Notation or value | Meaning |
| --- | --- |
| `<path>` | Host path. Relative paths are resolved from the command's working directory. |
| `<hash>` | Content address in `blake3:<64 lowercase hexadecimal digits>` form. |
| `<path-or-hash>` | A local file/path or an object resolvable from `--store`. |
| `<dur>` | Positive integer followed by no suffix, `tick`, `ticks`, `ns`, `us`, `ms`, or `s`. No suffix means ticks; one tick is one picosecond (1,000 ticks per nanosecond). |
| `*_nanos` | Unsigned integer duration in virtual nanoseconds. |
| `*_ticks` | Unsigned integer virtual-time or scheduler coordinate. |
| `*_basis_points` | Integer probability or factor measured in basis points. Probabilities accept `0..=10000`, where 10,000 is 100%. |
| `loss_millionths` | Integer link probability in `0..=1000000`, where 1,000,000 is 100%. |
| `field?` in this page | Optional field. The question mark is documentation notation and is not part of the TOML key. |
