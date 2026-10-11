# Implementation qualification record

**Status:** Checkpoint evidence; RFC-0026 remains an implementation in progress.
This record distinguishes qualified behavior from proposed contracts and public
service admission. The permission policy in appendix 13 and schema transition
in appendix 12 remain uninstalled. Serving identity remains generation eighteen.

## Qualified checkpoints

`410b9d4500` binds event replay consumers to their exact requested positions.
`4c9ac617a0` adds bounded observation of existing Hub scans. The latter changes
CLI behavior and native test/fleet fixtures; it does not change production Hub
permission, migration, provider, matching or coordination code. Documentation
commits do not imply additional runtime qualification.

| Surface | Completed qualification | Scope and limits |
| --- | --- | --- |
| Shared assessment/provider/runtime/HTTP contracts | 234 unit, integration and documentation tests passed; one ignored | Includes source-custody-independent advisory revision commitments and request-bound replay validation. |
| Production shared-library lint | Strict Clippy passed on all four shared libraries | This is separate from the broader all-target attempt described below. |
| Native Hub Core | 1,823 tests passed; 66 ignored, with PostgreSQL/MySQL features | Full regression of checkpoint `410b9d4500`; ignored database/CLI fixtures are separately qualified below. |
| CLI | 424 unit tests and 175 integration tests passed | Checkpoint `4c9ac617a0`; includes local/Hub command contracts, report policy, named-wait timeout defaults/bounds and invalid mutation arguments. |
| Real CLI and persistent SQL | Eleven acceptance cases passed | Real CLI processes call isolated transports backed by reopened production SQLite journals. The named-wait case includes six scenarios. These fixtures grant no public IAM authority. |
| PostgreSQL | 28 assessment backend cases passed | Source-built PostgreSQL 18.6 against a private fixture database, including replay, clock, authority and custody checks. |
| MySQL backend | 18 assessment backend cases passed | Source-built MariaDB 12.3.3. This does not qualify an Oracle MySQL server. |
| Maintenance and metadata libraries | 18 maintenance and 40 metadata tests passed; one metadata test ignored | Existing maintenance behavior and package metadata/trust parsing against the extracted shared code. |
| Worker and Console | WASM checks passed | Shared production service and client code of checkpoint `410b9d4500`. |
| Pure Nix evaluation | Passed | Includes current metadata and extended fleet declarations. |
| All application test targets | Passed | Mandatory hermetic compilation of application unit and integration targets; compilation is distinct from executing those targets. |
| Packaged KVM/fleet suite | Passed | Eleven actual CLI cases plus real SQL schedule, authority, status, stabilization and event replay cases. |
| Documentation | Local file-link and fence-balance checks passed | RFC chapters, review appendices and the user guide; these checks do not prove runtime semantics. |

The full Core run at unconstrained test concurrency encountered two SQLite
initialization lock timeouts. Both cases passed individually, and the entire
same native test binary then passed with eight test threads: 1,823 passed,
zero failed, 66 ignored. No production timeout, assertion or lock protection
was weakened to obtain that result.

The named-wait fixture qualifies real partial completion, an idle timeout, a
stalled initial HTTP lookup, a foreign initial receipt, a foreign successor
receipt and an already cancelled operation. It compares the durable receipt
before and after refused observations and verifies no new generation is
allocated. Partial completion preserves unknown/incomplete coverage; it is not
a clean vulnerability result. The packaged suite executes the same acceptance
case inside a KVM guest using the production packaged CLI.

## Hermetic build artifacts

Native, Worker and Console production artifacts for `410b9d4500` passed:

- Native: `/nix/store/wlhlz9zq615nhzymwb2pf9aylid0giyr-aos-hub-0.1.0`.
- Worker: `/nix/store/5ar6yva18z3acvp5pz6x55ndlqal9phc-aos-hub-worker-dist-0.1.0`.
- Console dependency: `/nix/store/gcyfhv4msfk5gb1n24f7x436qdvjvmkb-aos-hub-console-dist-0.1.0`.

The corresponding all-application compilation output was
`/nix/store/r1b9qwzsdk30dc9dzrqwimprnr6x8sl9-aos-test-targets-0.1.0`.
Its fleet output was
`/nix/store/9sha6j3pzhv2d942q488adc46nb4kgz5-aos-fleet-test-package-assessment-retained-pages-0`.

The extended `4c9ac617a0` fleet output is
`/nix/store/5iazpwmj0agcp2y52z18r7c2lcz7jc87-aos-fleet-test-package-assessment-retained-pages-0`.
Its VM script completed successfully and the build returned that output.
The extended all-application compilation passed and returned
`/nix/store/wld1cg4xwm80wg2rg3b1aqf58pda0qhr-aos-test-targets-0.1.0`.
An expected derivation path alone is not treated as a passing result.

## Reproduction entry points

Use the in-repository source-built entry point for hermetic qualification:

```text
aos-dev --release build check eval
aos-dev --release build check rust.aos-test-targets
aos-dev --release build check fleet.package-assessment-retained-pages
aos-dev --release build package aos-hub
aos-dev --release build package aos-hub-worker-dist
```

The production Native/Worker build graph includes the Console distribution.
The fleet build includes the production packaged CLI and native acceptance
fixture. Package-specific development tests use `nix develop -c cargo test`
with `--manifest-path crates/Cargo.toml`; direct CLI tests execute the resulting
binary, never `cargo run`. Private SQL connection-file variables and their
server qualifications are documented in the user guide. Credentials and
connection-file contents are not qualification artifacts.

This run used task-specific RAM-backed Cargo and Nix temporary build storage
because the shared storage pool was nearly full. Production derivation settings
remained selected, with no shared compiler caches. Source and build directories
were isolated; no shared daemon configuration or unrelated checkout was changed.

## Failures and unqualified requirements

Repository-wide aggregate checks fail at the pre-existing Crucible phase-one
decision-recording check. It expects `record_preemption_override`,
`decision_recorder_records_preemption_overrides_in_schedule` and
`decision_recorder_derives_default_rr_preemption_without_overflow`. The cited
source and check files are unchanged from the Hybrid base. The aggregate suite
has not passed. An earlier strict all-target Clippy run also rejects existing
test `unwrap`/`expect` calls and a needless-borrow fixture; its result must not be
replaced by the narrower production shared-library lint pass.

Public assessment calls remain denied because the proposed permissions and
role grants are not installed. Positive public Native/Worker/Hybrid service
and browser E2E qualification remains pending. Private fixture permissions and
successful physical executor cases do not substitute for that qualification.

The pure advisory scheduling commitment does not install durable feed triggers.
The generation-nineteen input projection and compatibility work remain subject
to appendix 12 approval, including first-admission serialization and preservation
of a feed revision arriving after a slot freezes its evaluation.

Remaining RFC work includes coalesced advisory/feed refresh and grouped source
health, tenant-wide streaming and dependency-aware event/delivery retention,
notification health/retention, remaining legacy-command parity, signed aggregate
inventory/evidence, hosted disposition and release-policy integration, and final
cross-mode qualification. This record does not claim that the full continuously
operating RFC service is complete or ready for production activation.
