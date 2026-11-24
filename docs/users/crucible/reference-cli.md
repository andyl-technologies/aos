# Crucible command-line reference

This page lists every global option, command, and subcommand of the
shipped `crucible` CLI, with accepted values and defaults. It is part of
the [Crucible reference](reference.md), which also defines the value
notation used in the tables.

## Command-line interface

### Global options

Global options may appear before or after the subcommand.

| Option | Accepted value and default | Purpose | Guide |
| --- | --- | --- | --- |
| `--seed <u64\|hex>` | Unsigned 64-bit decimal or `0x`-prefixed hexadecimal; otherwise `CRUCIBLE_SEED`, then one generated seed | Override the root entropy. | [Seed resolution](running.md#seed-resolution) |
| `--backend <auto\|qemu>` | `auto` (default), `qemu` | Select or discover the local backend. Production builds expose QEMU only. | [Backend discovery](running.md#backend-discovery) |
| `--daemon <addr>` | Host/port or HTTP endpoint | Send a supported lifecycle operation to a daemon instead of running locally. | [Daemon operation](daemon.md) |
| `--daemon-ca <path>` | Requires `--daemon` and the other client TLS paths | Authenticate an HTTPS daemon with this CA certificate. | [Daemon operation](daemon.md#connect-a-client) |
| `--daemon-cert <path>` | Requires `--daemon` and the other client TLS paths | Present this client certificate chain to an HTTPS daemon. | [Daemon operation](daemon.md#connect-a-client) |
| `--daemon-key <path>` | Requires `--daemon` and the other client TLS paths | Present this client private key to an HTTPS daemon. | [Daemon operation](daemon.md#connect-a-client) |
| `--trusted-unauthenticated-daemon` | Required for cleartext daemon access | Explicitly acknowledge an unauthenticated endpoint on a trusted network. Conflicts with daemon mutual TLS. | [Daemon operation](daemon.md) |
| `--qemu <path>` | Otherwise `CRUCIBLE_QEMU`, then the packaged path | Override the patched-QEMU executable. The plugin is still resolved through its own discovery order, and the resolved pair must pass identity validation. | [Backend discovery](running.md#backend-discovery) |
| `--plugin <path>` | Otherwise `CRUCIBLE_PLUGIN`, then the packaged path | Override the matching QEMU plugin. QEMU is still resolved through its own discovery order, and the resolved pair must pass identity validation. | [Backend discovery](running.md#backend-discovery) |
| `--store <path>` | Command-specific default below `--artifact-dir` | Set the content-addressed store root. | [Artifacts and store](running.md#artifacts-and-store-layout) |
| `--campaign-deployment <PATH>` | Otherwise `CRUCIBLE_CAMPAIGN_DEPLOYMENT`, then `/etc/crucible/packaged-executor.toml` | Select the guarded local campaign-executor deployment; incompatible with a daemon route. | [Campaign setup](campaigns-host.md#start-the-single-host-owner) |
| `--format <jsonl\|json\|table\|markdown>` | Terminal: `table`; non-terminal: `jsonl` | Select report rendering. `jsonl` and `json` are stable machine formats. | [Output formats](running.md#output-formats) |
| `--trace <path>` | Standard output | Write the canonical event-log stream to a file. | [Output formats](running.md#output-formats) |
| `--artifact-dir <path>` | `./.crucible` | Set the failure-artifact and default savepoint/report directory. | [Artifacts and store](running.md#artifacts-and-store-layout) |
| `-v`, `--verbose` | Repeatable; default count `0` | Reserved for diagnostic verbosity; the count is accepted but does not currently change output. | [Running](running.md) |
| `-q`, `--quiet` | Boolean; default off | Suppress non-essential output. | [Running](running.md) |
| `-h`, `--help` | Built in | Print top-level or subcommand help. | This reference |
| `-V`, `--version` | Built in | Print the Crucible version. | This reference |

Backend values:

| Value | Meaning |
| --- | --- |
| `auto` | Discover and validate the packaged QEMU/plugin pair. |
| `qemu` | Require the local patched-QEMU production backend. |

Production QEMU execution also requires `CRUCIBLE_RUN_STATE_ROOT` to name a
writable, durable directory. Crucible creates content-addressed scenario and
monotonic run subdirectories beneath it. Each run records exact Linux process
identities (PID, start-time ticks, and executable), staged replacements, and
the lifecycle transaction phase. A second live owner is rejected; after an
interrupted owner disappears, Crucible verifies or contains every recorded
process before admitting a new run. Missing, malformed, or version-mismatched
recovery records fail closed.

Every QEMU child also receives a nonzero, monotonically increasing process
generation before the plugin accepts fault commands. Terminal lifecycle
authorization, durable supervision records, and restored fault state must all
name that exact generation. A request or checkpoint from an earlier child is
rejected rather than being applied to its replacement.

Output-format values:

| Value | Meaning |
| --- | --- |
| `jsonl` | Newline-delimited canonical JSON records; preferred for streaming programs. |
| `json` | One JSON document. |
| `table` | Human-readable terminal table. |
| `markdown` | Markdown report, especially useful for retained triage output. |

### Commands

| Command | Purpose | Detailed guide |
| --- | --- | --- |
| `run` | Execute a scenario to a terminal condition. | [Running](running.md) |
| `verify` | Repeat a scenario and compare fingerprints and canonical logs, or compare artifacts. | [Reproduction](reproduction.md#verify-repeated-execution) |
| `selftest` | Run packaged determinism gates. | [Self-test](running.md#self-test) |
| `save` | Stop at a deterministic coordinate and export a savepoint. | [Savepoints](reproduction.md#savepoints) |
| `resume` | Continue from a savepoint or checkpoint. | [Resume](reproduction.md#resume) |
| `replay` | Validate and reduce a recorded reproduction artifact. | [Replay](reproduction.md#replay) |
| `search` | Explore a bounded schedule space. | [State-space search](exploration.md#state-space-search) |
| `fuzz` | Sample a scenario family using basic-block coverage. | [Coverage-guided fuzzing](exploration.md#coverage-guided-fuzzing) |
| `triage` | Cluster, deduplicate, and minimize the findings retained by a campaign snapshot. | [Findings and triage](exploration.md#findings-and-triage) |
| `debug` | Inspect a live daemon session at a coordinate; local artifact/savepoint execution currently fails closed. | [Debugging](debugging.md#debug-command) |
| `serve` | Run the remote lifecycle API. | [Daemon operation](daemon.md) |
| `campaign` | Author campaign inputs offline, and inspect or control a lazy campaign through the local daemon. | [Campaigns](campaigns.md) |
| `store` | Inspect or maintain a configured content store. | [Composed store](campaigns-store.md#inspect-and-collect-a-composed-store) |
| `completions` | Generate shell completion definitions. | [Shell completions](running.md#shell-completions) |

### `run`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SCENARIO` | Required | Canonical scenario TOML path or content hash. |
| `--until <quiescence\|virtual-time\|property\|stopped>` | Default `quiescence` | Select the terminal condition; see [terminal values](#terminal-and-save-boundary-values). |
| `--max-virtual-time <dur>` | Required with `--until virtual-time` | Stop with timeout after this virtual-time budget. |
| `--max-quanta <n>` | Optional | Stop at an exact scheduler-quantum boundary unless another terminal condition occurs first. |
| `--interactive` | Off | Pause at genesis and read interactive commands from standard input. |
| `--save-on <fail\|always\|never>` | Default `never` | Materialize an outcome savepoint only on failure, for every outcome, or never. |
| `--watch` | Off | Collect authenticated campaign-head updates alongside local-QEMU run evidence; other backends collect session status. |

`--save-on` values:

| Value | Meaning |
| --- | --- |
| `fail` | Save only a failing outcome. |
| `always` | Save passing, failing, and timeout outcomes. |
| `never` | Do not create an outcome savepoint. |

The current unattended local QEMU route admits only `never`; the other values
are parsed but refused before execution. Use [`save`](#save) for an exported
savepoint handle. See [lifecycle limits and timeout semantics](running.md#terminal-conditions-and-budgets)
and [current execution refusals](support.md#current-execution-refusals) before
treating an accepted CLI value as an implemented backend capability.

For unattended local QEMU `--until property`, the discovery stop observes an
assertion violation; run-supplied virtual-time and quantum limits do not enter
that stop. Lifecycle and deployment limits remain in force.

### `verify`

Exactly one of `SCENARIO` and `--compare` is required.

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SCENARIO` | Alternative to `--compare` | Scenario path or content hash to execute repeatedly. |
| `--runs <n>` | Default `2` | Number of executions to compare. |
| `--adversarial` | Off | Run under the hostile host-condition matrix. |
| `--bisect` | Off | On divergence, run deterministic divergence bisection and print its report. |
| `--compare <a> <b>` | Alternative to `SCENARIO` | Compare two existing reproduction artifacts using their embedded identities, without executing a scenario or generating a seed. |

### `selftest`

| Option | Required/default | Meaning |
| --- | --- | --- |
| `--gates <list>` | The three live-QEMU gates listed in [Self-test](running.md#self-test) | Run a comma-separated subset of those gates. Any other gate name is rejected. |

The production command always runs QEMU-backed gates. Test-double builds also
compile the test-only `--with-qemu` and `--corpus <path>` options; neither is
part of the shipped production interface.

Self-test honors the global `--format`, `--trace`, and `--quiet` options. JSONL
uses `selftest_gate`, `selftest_scenario`, and terminal `final_outcome` records.

### `save`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SCENARIO` | Required | Scenario path or content hash. |
| `--at <virtual-time\|quiescence\|property\|marker>` | Required | Select the save boundary; see [boundary values](#terminal-and-save-boundary-values). |
| `--label <name>` | Optional | Add a human-readable savepoint label. |
| `--max-virtual-time <dur>` | Required with `--at virtual-time` | Exact virtual-time coordinate at which to save; stagnation and overshoot fail closed. |
| `--property <assertion>` | Required with `--at property` | Assertion ID whose violated phase supplies the boundary. |
| `--marker <name>` | Required with `--at marker` | Guest-marker ID whose observation supplies the boundary. |
| `--out <path>` | Default below `--artifact-dir` | Select the exported savepoint-handle path. |

The current savepoint handle schema v6 records the authenticated Campaign
replay closure, exact boundary proof, and content-addressed predicate or
observation evidence. The reader rejects mismatched selectors, predicates,
terminal conditions, frontiers, undeclared property identities, and incomplete
replay closures. Earlier handle schemas fail closed during decoding.

A property or marker miss returns exit 3 without a handle. An explicit
`--trace` is still honored and ends with `save_boundary_failure`, preserving the
partial control trail for diagnosis.

### `resume`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SAVEPOINT` | Required | Authenticated `.crucible-savepoint` handle path. |
| `--until <quiescence\|virtual-time\|property\|stopped>` | Default `quiescence` | Select the resumed terminal condition. |
| `--max-virtual-time <dur>` | Required with `--until virtual-time` | Stop with timeout after this virtual-time budget. |
| `--interactive` | Off | Drive the resumed session from standard input. |
| `--watch` | Off | Collect live session-status updates. |

### `replay`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `ARTIFACT` | Required | v4 reproduction-artifact path; production replay requires the matching packaged QEMU/plugin identity. |
| `--check <original-log>` | Optional | After live replay succeeds, require byte-identical canonical JSONL output. |
| `--to <savepoint>` | Optional | Live-replay the artifact, then validate a target savepoint handle or checkpoint hash as its typed prefix. A v4 artifact can resolve its own terminal checkpoint hash without a separate store object. |
| `--bisect <other-artifact>` | Optional | Live-replay both artifacts, then locate their first evidence divergence. |
| `--bounded-scheduler-preemption` | Off | Inject and require authenticated bounded host scheduler preemption during live QEMU replay. |

The v4 artifact's live recipe declares its fingerprint evidence scope. Run,
verify, and fuzz use the full execution stream; search uses one terminal
sample per VM node. Interactive control recipes are rejected until exact command
timing can be reproduced.

### `search`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `SCENARIO` | Required | Scenario path or content hash. |
| `--strategy <bfs\|dfs\|guided>` | Default `bfs` | Expand breadth-first, depth-first, or by coverage guidance. |
| `--max-depth <n>` | Optional | Bound decision depth. |
| `--max-states <n>` | Default `1` | Bound materialized states. Set this explicitly for useful campaigns. |
| `--on-violation <stop\|collect>` | Engine default `stop` when omitted | Stop at the first property/timeout finding or continue within the supplied budget. |
| `--findings-out <path>` | Content-addressed path below `<artifact-dir>/findings`, written only when a finding is retained | Write the signed findings ledger to this path. An explicit path is written even when no finding is retained. |
| `--schedule-named-truths <path>` | Optional | Load schedule-named assertion truth data. |
| `--retained-evidence <path>` | Optional | Load authenticated backend-retained assertion evidence. |

Search policy values:

| Option value | Meaning |
| --- | --- |
| `--strategy bfs` | Expand the shallowest frontier first. |
| `--strategy dfs` | Follow a frontier deeply before returning to siblings. |
| `--strategy guided` | Use coverage feedback to prioritize frontiers. |
| `--on-violation stop` | Stop after the first counterexample. |
| `--on-violation collect` | Continue exploring within the configured budget and retain every distinct property or timeout finding. |

### `fuzz`

Supply the family either positionally or with `--family`, never both.

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `FAMILY` | Alternative to `--family` | Built-in name, family TOML path, or content hash. |
| `--family <path\|hash>` | Alternative to `FAMILY` | Explicit named form of the family input. |
| `--runs <n>` | Default `1` | Number of concrete family instances to run. |
| `--coverage <basic-block>` | Default `basic-block` | Select the coverage feedback signal. |
| `--corpus <path>` | Optional | Seed and regression corpus directory. |
| `--on-violation <stop\|collect>` | Default `stop` | Stop at the first property/timeout finding or retain findings through the run budget. |
| `--findings-out <path>` | Content-addressed path below `<artifact-dir>/findings`, written only when a finding is retained | Write the signed findings ledger to this path. An explicit path is written even when no finding is retained. |

### `triage`

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `--campaign-socket <path>` | Required | Connected campaign service socket. |
| `--principal <principal>` | Required | Authenticated campaign principal. |
| `NAME` | Required | Canonical campaign name. |
| `--snapshot <snapshot>` | Required | Exact authenticated campaign snapshot whose retained findings are triaged. |
| `--policy <coarse\|default\|fine\|exact>` | Default `default` | Select how much failure evidence participates in a cluster signature. Finer policies split more findings. |
| `--minimize <none\|representative\|all>` | Default `representative` | Skip minimization, minimize one deterministic representative per cluster, or minimize every selected representative. |
| `--report <dir>` | Default below `--artifact-dir` | Write per-cluster reports here. |
| `--recompute-signatures` | Off | Recompute signatures and fail if retained evidence drifts. |

Triage policy values:

| Option value | Meaning |
| --- | --- |
| `--policy coarse` | Group aggressively using coarse evidence. |
| `--policy default` | Use the normal failure-signature policy. |
| `--policy fine` | Include more evidence and split more findings. |
| `--policy exact` | Require exact signature evidence. |
| `--minimize none` | Report representatives unchanged. |
| `--minimize representative` | Minimize the content-address-least representative per cluster. |
| `--minimize all` | Minimize every selected representative. |

### `debug`

Exactly one target is required: positional `ARTIFACT|SAVEPOINT` or `--session`.
The four coordinate selectors are mutually exclusive.

| Argument or option | Required/default | Meaning |
| --- | --- | --- |
| `ARTIFACT\|SAVEPOINT` | Alternative to `--session` | Attach to a retained artifact or savepoint. |
| `--session <id:epoch:seed>` | Alternative to positional target | Attach to a running daemon session. The seed is exactly 64 lowercase hexadecimal digits. |
| `--at <coord>` | Optional coordinate | Open at a virtual-time or node-icount coordinate. |
| `--at-event <seq>` | Optional coordinate | Open at an event-log sequence. |
| `--at-failure` | Optional coordinate | Open at the recorded failure point. |
| `--at-checkpoint <hash>` | Optional coordinate | Open at a checkpoint content address. |
| `--node <id>` | Optional | Select the node whose gdbstub is attached. |
| `--gdb-listen <addr>` | Optional | Listen for mediated GDB-protocol clients here. |
| `--read-only` | Off; conflicts with `--allow-mutate` | Preserve the canonical run and prohibit mutation. |
| `--allow-mutate` | Off | Fork a non-canonical debug branch for mutation. |
| `--checkpoint-stride <n>` | Optional | Bound reverse-step replay distance with opportunistic checkpoints. |
| `--record-transcript <path>` | Off | Exclusively create a bounded branch-local guest-channel transcript. |
| `--guest-idle-timeout <dur>` | `30s` | Fail and clean up when a guest agent produces no response for this duration. |

Debugger verbs:

| Verb | Arguments | Meaning |
| --- | --- | --- |
| `attach-gdb` | None | Open the mediated gdbstub channel. |
| `fork-debug` | None | Create the explicit non-canonical whole-world branch required for guest introspection. |
| `goto` | `<coord>` | Move to another accepted debug coordinate. |
| `reverse-step` | `instruction`, `quantum`, `event`, `assertion`, or `timer` | Step backward by one deterministic grain. |
| `reverse-continue` | `<condition>` | Continue backward to a matching condition. |
| `exec` | `-- <argv...>` | Execute argv directly through the forked guest agent. |
| `pty` | `[--columns <n>] [--rows <n>] -- <argv...>` | Bridge a local terminal to a guest PTY. |
| `ssh` | None | Bridge bytes to the SSH server configured in the guest agent. |

### `serve`

| Option | Required/default | Meaning |
| --- | --- | --- |
| `--listen <addr>` | Required | Bind the HTTP/2 lifecycle API. TLS is selected by the server TLS options. |
| `--max-sessions <n>` | Optional; must be greater than zero | Cap concurrent live sessions. |
| `--production-qemu` | Off | Host inline scenarios with the packaged production QEMU lifecycle instead of the quiescent API-test loop. |
| `--qemu-rendezvous-ticks <n>` | Optional positive count; production QEMU only | Cap production-QEMU runs at this deterministic exact-tick rendezvous interval. |
| `--qemu-quantum-budget <n>` | Optional | Limit the number of scheduler quanta in a production-QEMU session. |
| `--read-only` | Off | Permit query/watch calls and reject mutations. |
| `--tls-cert <path>` | Required with the other server TLS paths | Server certificate chain. |
| `--tls-key <path>` | Required with the other server TLS paths | Server private key. |
| `--client-ca <path>` | Required with the other server TLS paths | CA used to authenticate client certificates. |
| `--trusted-unauthenticated-bind` | Required for cleartext | Explicitly trust an unauthenticated bind; conflicts with TLS. |
| `--debug-role <sha256=capability,...>` | Repeatable; authenticated server | Map a client leaf-certificate fingerprint to `observe`, `control`, `mutate`, `shell`, and/or `admin`. |

The following `serve` options host the local campaign service. Every one
except `--campaign-socket` requires `--campaign-socket`. See
[Start the single-host owner](campaigns-host.md#start-the-single-host-owner).

| Option | Required/default | Meaning |
| --- | --- | --- |
| `--campaign-socket <path>` | Optional | Host the local campaign service on this managed Unix socket. |
| `--campaign-socket-mode <octal>` | Default `600` | Set the managed campaign socket's Unix permission bits in octal. |
| `--campaign-state <path>` | Optional | Retain local campaign objects and refs below this existing directory. |
| `--campaign-policy <path>` | Optional | Load the strict local campaign peer policy from this file. |
| `--campaign-store <path>` | Optional | Load a strict composed campaign repository-store deployment. |
| `--campaign-component-authority <path>` | Optional | Load distinct planner/debugger component authority keys from this file. |
| `--campaign-import-manifest <path>` | Repeatable; conflicts with `--read-only` | Import verified campaign creation artifacts before binding the socket. |
| `--campaign-runtime <name>` | Repeatable; requires `--campaign-component-authority` and `--campaign-executor-socket`; conflicts with `--read-only` | Attach the packaged planner and an authenticated local executor to a campaign. |
| `--campaign-runtime-all` | Requires `--campaign-component-authority`, `--campaign-executor-socket`, and `--campaign-packaged-executor`; conflicts with `--campaign-runtime` and `--read-only` | Attach every authenticated campaign in the bounded local catalog. |
| `--campaign-executor-socket <path>` | Repeatable; conflicts with `--read-only` | Connect one attached campaign runtime to this owner-only Unix socket; repeat in runtime order unless a packaged pool shares one endpoint. |
| `--campaign-packaged-executor <path>` | Requires `--campaign-component-authority`, `--campaign-executor-socket`, and `--production-qemu`; conflicts with `--read-only` | Start one scenario-catalogued packaged QEMU pool from this deployment file. |
| `--campaign-maintenance-interval-ms <milliseconds>` | Requires `--campaign-store`; conflicts with `--read-only` | Run bounded campaign-store maintenance at this fixed cadence. |
| `--campaign-maintenance-write-back-transfers <n>` | Requires `--campaign-maintenance-interval-ms` | Complete at most this many write-back transfers per maintenance pass. |
| `--campaign-maintenance-s3-nodes <n>` | Requires `--campaign-maintenance-interval-ms` | Visit at most this many S3 leaves per maintenance pass. |
| `--campaign-maintenance-s3-uploads <n>` | Requires `--campaign-maintenance-interval-ms` | Abort at most this many unfinished uploads per visited S3 leaf. |

### `campaign`

`campaign` accepts two options before its subcommand. Both are omitted for
offline authoring, validation, and archival subcommands.

| Option | Meaning |
| --- | --- |
| `--socket <path>` | Connected daemon socket. |
| `--principal <principal>` | Authenticated principal. |

In the tables below, `NAME` is the canonical campaign name and every
`--snapshot <SNAPSHOT>` is required and names one exact authenticated campaign
snapshot. `BASIS` abbreviates the mutation basis
`NAME --expected <SNAPSHOT> --command <COMMAND>`: the snapshot the mutation
expects to advance and a stable lowercase hexadecimal idempotency key.
Bracketed options are optional. The [campaign guide](campaigns.md) gives the
workflows.

Offline authoring, validation, and archival:

| Subcommand | Arguments and options | Purpose |
| --- | --- | --- |
| `fixture worked-network` | `--output <DIR>`; `[--kernel <FILE> --root-image <FILE> --qemu <FILE> --plugin <FILE>]`, which must be supplied together | Generate the adaptive network-recovery reference campaign into a new directory. The four optional paths select the AOS-built kernel, the immutable `root.ext4` of the AOS Envoy network guest package, and the packaged QEMU and matching plugin for the executable fixture. |
| `validate-import` | `<MANIFEST>...` | Validate strict campaign import manifests without opening repository state. Repeated manifests share one bound. |
| `validate` | `NAME` or `--policy <FILE>`, never both | Authenticate a named campaign through the connected service, or validate one canonical binary policy record offline. |
| `scenario compile` | `<INPUT> --output <DIR>` | Compile canonical scenario TOML and an empty genesis schedule into a new directory holding `scenario.bin`, `schedule.bin`, and `import.toml`. |
| `configuration compile` | `<SCENARIO> <SCHEDULE> --output <DIR>` | Compile a nonempty canonical Schedule V4 against one scenario into an importable configuration bundle. |
| `schedule compile` | `<INPUT> --output <OUTPUT>` | Compile a strict TOML decision list into canonical Schedule V4 bytes. |
| `policy compile` | `<INPUT> [--scenario <SCENARIO>] --output <OUTPUT>` | Compile a strict TOML policy into its canonical binary record. `--scenario` resolves selectable IDs and tag predicates. |
| `lineage compile` | `<INPUT> --output <OUTPUT>` | Compile a strict TOML lineage into its canonical binary record. |
| `archive transfer` | `--source-state <path> --source-policy <path> --source-store <path> --source-campaign <name> --snapshot <snapshot-id> --mode <metadata\|findings\|debug\|executable\|mirror> --destination-state <path> --destination-policy <path> --destination-store <path> --archive <name>`; `[--retain <content-id>]...` (mirror archives only), `[--campaign <name>]` (executable archives), `[--minimum-durable-placements <n>]` (default `1`), `[--allow-deferred-write]`, `[--maximum-checkpoint-bytes <bytes>]` (default `1073741824`) | Transfer one exact snapshot between stopped deployment owners. |
| `archive inspect` | `--state <path> --policy <path> --store <path> --archive <name>` | Authenticate one named archive in a stopped deployment. |

Creation and lifecycle:

| Subcommand | Arguments and options | Purpose |
| --- | --- | --- |
| `create` | `NAME --lineage <FILE> --policy <FILE> [--start-command <COMMAND>]` | Create a named campaign from canonical imported lineage and policy records. `--start-command` resumes it immediately with that idempotency key. |
| `derive` | `<SOURCE> --snapshot <SNAPSHOT> <TARGET> [--policy <FILE>]` | Derive a new named campaign from one exact source snapshot, optionally activating a compiled policy. |
| `attach` | `NAME --executor-socket <PATH>` | Attach one live runtime to a local executor endpoint. The path is absolute. |
| `start` | `BASIS` | Begin issuing work for a newly created campaign. |
| `resume` | `BASIS` | Begin or resume issuing campaign work. |
| `pause` | `BASIS [--active <drain\|checkpoint\|retry>]` (default `drain`) | Pause new work. `drain` lets accepted attempts finish, `checkpoint` captures exact checkpoints for them, and `retry` cancels them and leaves their work retryable. |
| `stop` | `BASIS [--seal]` | Complete a campaign; `--seal` also seals it against accidental future mutation. |
| `unseal` | `BASIS` | Re-enable mutation of a sealed campaign. |
| `budget` | `BASIS add <ATTEMPTS> [--proposals <PROPOSALS>]` (default `0`) | Grant additive proposal and attempt budget. |
| `steer` | `BASIS --policy <POLICY>` | Activate an imported compatible policy for future work. |
| `pin` | `BASIS <CONFIGURATION> [--tier <thin\|exact>] [--reason <TEXT>]` (default tier `thin`) | Add or update one semantic configuration pin. `thin` retains semantic replay inputs; `exact` retains the complete portable exact closure. |
| `unpin` | `BASIS <CONFIGURATION> [--reason <TEXT>]` | Remove one semantic configuration pin. |

Branching and captures:

| Subcommand | Arguments and options | Purpose |
| --- | --- | --- |
| `branch` | `NAME --expected <SNAPSHOT> --branch-point <BRANCH_POINT> --parent <CONFIGURATION_ARTIFACT>` plus the selection options below | Submit one finite additive operator branch request. |
| `choice-value encode` | `NAME --snapshot <SNAPSHOT> --opportunity <OPPORTUNITY> --member <NAME=VALUE>...` | Encode a complete named atomic group tuple for `campaign branch --value`. |
| `capture-attempt` | `NAME --snapshot <SNAPSHOT> --attempt <ATTEMPT> --command <COMMAND>` | Replay a completed next-choice attempt to an exact pending-choice checkpoint. |
| `capture-status` | `NAME --snapshot <SNAPSHOT> --request <REQUEST>` | Inspect the authenticated outcome and retained root of one capture. |
| `select-capture` | `NAME --snapshot <SNAPSHOT> --request <REQUEST> --command <COMMAND> --stop <CONDITION>` | Admit an exact-source continuation from a Ready capture, stopping at the later condition reached after the pending choice is answered. |

`branch` selection options:

| Option | Required/default | Meaning |
| --- | --- | --- |
| `--command <COMMAND>` | Required unless `--all`; conflicts with `--all` | Exact operator idempotency key. |
| `--opportunity <OPPORTUNITY>` | Required with `--domain` unless `--selector` is used | Exact choice-opportunity ID reached at the parent. |
| `--domain <DOMAIN>` | Required with `--opportunity` unless `--selector` is used | Exact effective choice-domain ID. |
| `--selector <SELECTOR>` | Repeatable alternative to `--opportunity`/`--domain` | Resolve one opportunity by conjunctive declaration names, IDs, or tags. |
| `--instance <INSTANCE>` | Optional; requires `--selector` | Exact opportunity instance filter. |
| `--selector-scan-limit <COUNT>` | Default `256` | Maximum authenticated opportunities examined during selector resolution. |
| `--value <VALUE>` | Repeatable; one of `--value`, `--generator`, or `--all` is required | Finite value: `true`, `false`, `i64:N`, `u64:N`, `discrete:ID`, or `group:HEX`. |
| `--generator <GENERATOR>` | Alternative to `--value` and `--all` | Deterministic candidate-generator ID instead of finite values. |
| `--all` | Alternative to `--value` and `--generator`; conflicts with `--proposals` | Exhaust the authenticated finite domain under the active exhaustive policy. |
| `--proposals <COUNT>` | Required for a generator; otherwise defaults to the value count | Maximum proposals. |
| `--attempts <COUNT>` | Default `1` | Maximum newly admitted attempts. |
| `--stop <CONDITION>` | Default `next-choice` | Primary stop: `next-choice`, `terminal`, `boundary:NAME`, `virtual-time-ps:N`, `events:N`, `execution-quanta:N`, or `virtual-time-or-execution-quanta:TIME:QUANTA`. The active policy's attempt deadlines also apply. |

Inspection and explanation:

| Subcommand | Arguments and options | Purpose |
| --- | --- | --- |
| `list` | `[--after <NAME>] [--limit <COUNT>] [--pages <COUNT>]` (defaults `32` and `1`) | List authenticated current campaign heads. |
| `status` | `NAME` | Print the current authenticated campaign head and lifecycle state. |
| `watch` | `NAME [--after <SNAPSHOT>]` | Return the latest coalesced head after an optional snapshot cursor. |
| `snapshot` | `NAME --snapshot <SNAPSHOT>` | Inspect one exact historical campaign snapshot. |
| `compare` | `NAME --left <SNAPSHOT> --right <SNAPSHOT>` | Compare two exact historical campaign snapshots. |
| `report` | `NAME --snapshot <SNAPSHOT> [--after <CURSOR>] [--limit <COUNT>] [--pages <COUNT>]` (defaults `8` and `1`) | Report snapshot-bound outcomes, exploration state, and estimator evidence. |
| `graph`, `choices`, `frontier`, `findings` | `NAME --snapshot <SNAPSHOT> [--after <CURSOR>] [--limit <COUNT>] [--pages <COUNT>]` (defaults `8` and `1`) | Read one authenticated page of the temporal graph, discovered choice opportunities, continuation states, or canonical failure findings. |
| `graph-object` | `NAME --snapshot <SNAPSHOT> --key <KEY>` | Inspect one exact object named by the authenticated graph. |
| `choice-object` | `NAME --snapshot <SNAPSHOT> --opportunity <OPPORTUNITY> --kind <declaration\|domain>` | Inspect the reusable selectable declaration or the exact effective choice domain named by an authenticated choice. |
| `frontier-object` | `NAME --snapshot <SNAPSHOT> --request <REQUEST>` | Inspect one exact branch request and its current continuation state. |
| `request-attempts` | `NAME --snapshot <SNAPSHOT> --request <REQUEST> [--after <PROPOSAL>] [--limit <COUNT>] [--pages <COUNT>]` (defaults `8` and `1`) | Read authenticated execution bases and additional causes for one branch request. |
| `explain` | `NAME --snapshot <SNAPSHOT> --opportunity <OPPORTUNITY> --request <REQUEST>` | Explain one exact choice and frontier-request basis. |
| `explain-finding` | `NAME --snapshot <SNAPSHOT> --finding <FINDING>` | Explain one exact finding and its reproduction basis. |
| `explain-attempt` | `NAME --snapshot <SNAPSHOT> --attempt <ATTEMPT>` | Explain one exact attempt, proposal, and completion basis. |
| `rankings` | `NAME --snapshot <SNAPSHOT> --step <STEP> [--pages <COUNT>] [--policy-groups] [--branch-point <BRANCH_POINT>] [--source <REQUEST>] [--top <COUNT>]` (default `--pages 16`) | Rank candidates or policy epochs across an authenticated planner-step chain. |

Findings:

| Subcommand | Arguments and options | Purpose |
| --- | --- | --- |
| `replay` | `NAME --snapshot <SNAPSHOT> --finding <FINDING> [--minimized]` | Replay one authenticated finding reproduction through its pure oracle; `--minimized` replays the authenticated minimized reproduction when present. |
| `triage` | `NAME --snapshot <SNAPSHOT>` plus the [`triage`](#triage) policy, minimization, and report options | Project and minimize the authenticated findings retained by one snapshot. |
| `debug` | `NAME --snapshot <SNAPSHOT> --finding <FINDING> --node <ID> [--gdb-listen <ADDR>] [--writable]` (default listener `127.0.0.1:0`) | Open an authenticated retained finding checkpoint in the debug relay. `--writable` forks a private non-canonical branch before exposing the GDB relay. |
| `finding-bundle export` | `NAME --snapshot <SNAPSHOT> --finding <FINDING> --source-state <PATH> --source-policy <PATH> --source-store <PATH> --output <DIR> [--maximum-checkpoint-bytes <BYTES>]` (default `1073741824`) | Export one finding and its complete executable archive from a stopped owner into a new directory. |
| `finding-bundle verify` | `<DIR> [--role <ROLE>] [--exact]` | Verify archived evidence offline; `--exact` repeats the retained production boundary in a fresh local QEMU lifecycle. |
| `finding-bundle midpoint` | `<DIR> --node <ID> [--role <ROLE>] [--maximum-checkpoint-bytes <BYTES>]` | Open an archived exact checkpoint in a private read-only QEMU session with this node's gdbstub attached. |
| `finding-bundle fork-write` | The `midpoint` arguments plus `[--register <N>]` (default `0`), `[--xor-mask <MASK>]` (default `1`), `[--serve]` | Fork a second private midpoint and prove one non-canonical register write to the low byte of the GDB register; `--serve` keeps serving the writable branch to a local GDB client. |
| `finding-bundle branch` | `<DIR> --value <VALUE> --output <DIR> [--timeout-seconds <SECONDS>]` (default `300`) | Execute a declared alternate choice for the first retained declared choice from the imported executable archive into a new owner-only directory. |

`--role` selects the retained replay pass: `minimization-original`,
`minimization-selected`, `verification-original` (default), or
`verification-selected`.

### `store`

Every `store` subcommand names a strict composed repository-store deployment
file, written `STORE` below.

| Subcommand | Arguments and options | Purpose |
| --- | --- | --- |
| `status` | `<STORE>` | Describe one exact admitted store graph without accessing object bytes. |
| `ensure` | `<CONTENT_ID> --in <STORE>` | Read and authenticate one complete object without repair or promotion. |
| `verify` | `<STORE>` | Authenticate every bounded physical placement in one stable generation. |
| `gc` | `--state <path> --policy <path> --store <path> --journal <path>` then `plan`, `cancel`, or `apply` | Stopped-owner garbage collection. `plan` inventories exact roots and persists a non-destructive deletion plan, `cancel` durably cancels a planned journal before deletion begins, and `apply` revalidates every generation and applies one persisted plan. The owner lock of the `--state` directory must be free. |
| `transform packed` | `--store <path> --journal <path> [--node <node>]` then `plan` or `apply` | Repack one exact packed-leaf generation. `--node` is optional only when exactly one packed graph node exists. |
| `credentials refresh` | `<STORE>` | Reload current credential files and validate every bound capability. |
| `cleanup incomplete-packs` | `--state <path> --policy <path> --store <path> [--node <node>]` | Under a stopped owner, reclaim complete and staging packs absent from the authenticated index. |
| `repair placement` | `<CONTENT_ID> --in <STORE> --source <NODE> --target <NODE> --state <PATH> --policy <PATH> [--maximum-bytes <BYTES>]` (default `1073741824`) | Restore one physical placement from an independently authenticated peer. `--source` supplies authenticated bytes, `--target` names the placement that may be replaced, and the command refuses a running service whose owner lock on `--state` is held. |

### `completions`

`completions SHELL` writes a completion definition to standard output.

| `SHELL` | Output |
| --- | --- |
| `bash` | Bash `complete` definition. |
| `elvish` | Elvish argument completer. |
| `fish` | Fish `complete` definition. |
| `powershell` | PowerShell argument completer registration. |
| `zsh` | Zsh `_crucible` completion definition. |

### Terminal and save-boundary values

| Value | Used by | Meaning |
| --- | --- | --- |
| `quiescence` | `run --until`, `resume --until`, `save --at` | Stop when the scheduler has no immediately runnable work. This is the default terminal condition. |
| `virtual-time` | `--until`, `save --at` | Stop at the positive `--max-virtual-time` duration. |
| `property` | `--until`, `save --at` | Stop on a property verdict; `save` requires `--property` and selects that assertion's violated phase. |
| `stopped` | `--until` only | Stop only after an explicit stopped state. |
| `marker` | `save --at` only | Save after observing the named `--marker`. |

Interactive command keywords and current payload limitations are documented in
[Interactive control](debugging.md#interactive-run-control).

## Output, artifacts, and exit status

JSON and JSONL are stable programmatic formats. Tables and Markdown are
presentation formats. The event trace is distinct from diagnostic output; use
`--trace` and `--quiet` when a job needs a clean machine stream.

The content-addressed store contains scenario forms, schedules, checkpoints,
and related execution objects. A reproduction artifact records inputs and the
schedule needed to reproduce a result. Signal-fault reproduction artifacts
also embed every reachable normalized trace/spatial/sampler object, authenticate
each object while restoring it into an isolated in-memory store, and include
mutation provenance when search changed a trace or mapping. A savepoint handle
names a checkpoint for `resume` and debugger attachment. Preserve every
store object referenced by exported handles; reproduction artifacts carry their
own signal closure.

Process exit statuses are listed once, in
[Running Crucible](running.md#exit-codes).

Scripts should branch on the status class and consume JSON/JSONL output. Human
diagnostic wording may change. See [Troubleshooting](troubleshooting.md) for
cause-oriented guidance.
