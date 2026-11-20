# Qualification executors

This page describes the native executors that run
[release qualification](qualification.md) cases: how they are packaged, the
scenarios they map, the requests and reports they exchange with the
coordinator, and the setup an operator must complete before a campaign.

## Native executors

`lib.testing.mkQualificationExecutor` (from `lib/testing`) packages a runner
with explicit `platform`, `identity`, `scenarios`, absolute `workRoot`, and
`timeoutSeconds`. `scenarios` maps case policy IDs, including `claim-<claim-id>`, to absolute executables in
AOS-built Nix closures. Missing implementations fail; an empty adapter is never
a passing gate. Environment-specific adapters and remote macOS transport must
be provisioned before a campaign. All source regression groups are exposed at
`checks.qualification.<requirement-id>` and `checks.qualification.all`.

The native ability gates are `ability-native-activation`,
`ability-native-kubernetes`, `ability-native-recovery`,
`ability-crucible-baseline`, and `ability-native-adapter-matrix`. They use release scope so each staging case
binds the complete finalized non-control artifact set, including the exact
package, native transaction, handler, and image records carried by the release.
A change to the case subjects, release-test policy, executor, or environment
invalidates its observation.

Native package tests use the signed `aos.package.qualification` companion,
which carries each package's smoke test (the `smokeTest` recipe argument). Its
closed probe declarations name exact package/output selectors; the frozen
artifact bindings select immutable payload roots. Release approval validates
the companion's exact bytes and retained store identity, rather than
reconstructing an interface or provider catalog. A package smoke test covers
only its declared package-function claim. It does not establish a
whole-system activation or recovery claim.

The release policy carries `aos.qualification.native-operation-spec`, with an
explicit required operation set and independently checked cohorts. Each cohort
has its own `aos.qualification.native-operation-matrix-spec` and selected
baseline or scenario evaluation. The complete scenario registry, including
interruption, cancellation, rejection, and teardown cases, defines coverage;
a focused subset cannot satisfy the release requirement.

A scenario retains the original authored modules and its immutable evaluation
descriptor. The configured executor registry commits the exact fixture archive,
original store inventory, and evaluation selections at build time. Its executor
identity binds those commitments. The runner verifies them before replaying the
scenario against authenticated candidate inputs. These are executor-authorized
scenario inputs; they are distinct from the candidate's signed boot baseline.
Ambient store paths or a fixture's self-reported inventory do not supply that
authority.

A selected operation retains its checked desired graph and exact graph digest. Each dispatched attempt is
identified by transaction, effect, semantic revision, action, and durable
journal sequence. Invocation and recovery observations must match that exact
attempt. An observation for another revision, backend, action, or sequence
cannot satisfy its cell.

Live flights retain checked native journal inspection alongside independent
ownership records from the host system and backend, and foreign-state
snapshots. Pending intent, completed outcomes, and committed output mappings
are distinct results. Interruption and recovery cases must show dependent
nonexecution after failure, safe handling of incomplete tails, and the exact
ownership and foreign-state results required by the cell. Removal decisions
come from the transaction's explicit `retire` list and target retained or
already durably retired effects; omission from a desired graph does not
authorize retirement.

A native rejection result must identify the selected graph and the rejected
attempt, and independently establish that no prohibited dispatch or external
mutation occurred. Schema checks, mocked callbacks, and a successful source
regression cannot substitute for live domain observations. The source-built
`aos.qualification.native-runtime-audit` checks generic runtime boundaries
separately; passing it does not cover Kubernetes, storage, services, boot, or
any other domain.

Source-candidate regression derivations and release staging cases remain
separate. Release approval requires fresh executor observations for the exact
frozen subjects and acceptance checks. Whole-system native fleet testing is
incomplete until every applicable domain operation and recovery case has
produced its required results. An unfinished scenario must leave the gate
unsatisfied. An x86 fleet does not establish direct aarch64 execution.

Kubernetes testing requires actual native package modules, authenticated
APM deployment, observed readiness and exact object revisions, and verified
replacement and removal behavior. A package-function probe or a fabricated
companion cannot impersonate the finalized Kubernetes or system manager
artifacts for a production flight.

The x86 release executor maps the remaining implemented native policy IDs to
ability scenarios for the Crucible baseline, adapter matrix, image rollout,
and recovery. Activation uses the ordinary report scenario while its source
regression runs the production package-module and APM configuration path.
Each mapped scenario selects the exact finalized server QCOW2,
slot-A UKI, metadata, unsigned assembly, and finalized-set objects from the
downloaded release case.
It verifies their byte identities and cross-bindings, extracts the UKI's initrd,
and checks the published native host and initrd transaction, package, evaluation,
and trusted artifact manifest (`admission.json`) roots before booting that
QCOW2 with KVM, UEFI Secure Boot, and a software TPM. It then confirms through
the guest's recorded running generation, booted UKI digest, kernel, root hash,
and host trusted artifact manifest and retained transaction identities that
execution stayed on those published subjects. A checked desired graph alone
does not show that its effects ran.

The production-only image-rollout scenario additionally requires the frozen
predecessor manifest and its downloaded object bundle. It rejects a missing or
mismatched bundle before boot, validates the predecessor's complete finalized
server image controls, and starts independent healthy and failed-health flights
from exact copies of that predecessor QCOW2. The candidate is obtained only by
retaining the image's baked authenticated registry trust anchor, redirecting it
to the bounded HTTPS staging Hub origin, and replacing its channel with the
exact finalized release-version tag. The healthy flight independently observes
the health hook and native journal before allowing physical boot commit, then
checks that expiry retires both rollout roots and retained UKIs. The failed-health
flight observes the exact candidate boot before releasing the failure hook,
then checks the exact predecessor boot, retained roots, native journal, and
terminal fallback before allowing physical commit. A missing predecessor,
untrusted registry configuration, inaccessible staging Hub, non-matching image
object, absent branch result, or incomplete exact-boot observation leaves no
scenario report and therefore cannot satisfy the gate.

The scenario also reconstructs the complete published NAR graph rooted at the
release's `aos`, `apm`, `apr`, and `packageRuntime` outputs. It verifies every
downloaded NAR and narinfo relationship in an initially empty private Nix store,
exports that checked graph, imports it into the published guest, and compares
the guest's registered NAR hashes and references with the downloaded records.
Executor-owned observation fixtures remain separate from the release subjects.
Their immutable artifacts and candidate runtime selection must be retained and
bound to the observation. They cannot replace a signed package companion or
alter published subjects to manufacture a passing production claim.

Native boot results bind the image-owned host and initrd transaction,
packages, evaluation snapshot, and trusted artifact manifest roots to the
published assembly. Read-only inspection of the native effects journal
distinguishes desired configuration, pending durable dispatch intent, and
committed output mappings. It does not repair incomplete tails or treat graph
digests as a check of live state. Live operation results record the exact
transaction, effect, revision, action, and journal sequence alongside
independently observed backend ownership and foreign-state snapshots. A
source-built native runtime audit is separate from domain tests; its success
does not satisfy a fleet scenario that has not completed its own native
operation and recovery checks.

After provisioning through the published `apm`, implemented native fleet
scenarios drive
the published `aos`, `apm`, `apr`, and package runtime paths in the guest. The
recovery case also observes fresh host authority and resource incarnations
after reboot. A passing scenario writes a fresh canonical report in the private
executor attempt. No precreated report under
`/run/aos-release/qualification-reports` can satisfy these mapped staging cases.

The runner reads a canonical v2 executor request on stdin. It verifies every
anonymous HTTPS download's size and SHA-256, retains it under a hashed name,
and writes `request.json`, `scenario-registry.json`, and `objects.json` in a
private attempt directory. The configured scenario receives the request on
stdin and runs in that directory with no inherited environment. `objects.json`
maps artifact IDs to the verified local paths. The object set contains each
case subject and the complete transitive graph named by its manifest
relationships, including signed narinfo and dependency artifacts. Scenarios
use AOS-built tools and the published image's normal provisioning and
serial/SSH interfaces.

The scenario emits `QualificationExecutorResponse`. Its observation must
contain the exact case digest, acceptance checks, numeric measurements, assessment
and applicable environment/capability results. Include the predecessor for update
claims. Set
`executor_digest` to the SHA-256 of the retained scenario registry bytes;
its store paths bind the executable closures. Include the actual non-sensitive
environment inventory in both `qualification.environment` and `report.environment`,
and set `environment_digest` to its canonical JSON SHA-256. Retain the assessment
in `report.assessment` as well as the structured observation. For A1, use the
reviewed profile digest as `environment_digest` and omit the tested inventory.
Record real UTC times and measured workload counts for direct execution. The
runner checks these bindings and retains response bytes, stdout,
stderr, and failures. Coordinator attempts retain each request and returned
response, including rejected results. Never overwrite a failed attempt.

Scenario programs can delegate the request binding and canonical response
assembly to the installed CLI. Write a canonical report in the attempt
directory, then run:

```sh
aos maintain release step qualification respond \
  --request request.json \
  --scenarios scenario-registry.json \
  --report scenario-report.json \
  --identity linux-x86-v1
```

Linux disk scenarios run QEMU and their other executables from the AOS build-host
package set while using firmware from the image's target package set. ARM64 TCG
images can therefore run on an x86_64 Linux host, and their inventory records
that outer host separately from the ARM64 guest. x86_64 disk tests still
require an x86_64 host with KVM.

The x86_64 Linux executor includes a native program for its staging
container claim. It reconstructs an OCI layout only from the anonymously
downloaded objects, imports that layout into a private AOS-built containerd and
runc instance, and runs ten bounded create, network, state, stop, and remove
cycles. The program retains the runtime import, HTTP, container, inspection,
and shutdown logs in the executor attempt. It records the host CPU, kernel,
resources, container runtime, cgroup, network, and volume identities directly
from the executing machine.

The ARM64 container claim uses the report-import adapter. Provision the ARM64
TCG guest on the recorded x86_64 host, execute the same lifecycle checks with
the exact downloaded candidate, and retain a report containing all three
observed layers. Build `mkQualificationContainerScenario` with `reportOnly = true`
for the guest-side collector. It writes the raw `scenario-report.json` after
all lifecycle checks and does not issue an executor response. The host
collector must attach its observed physical and QEMU inventory, then bind and
validate the combined report through `qualification respond`. A guest-local two-layer report cannot satisfy this profile;
report import does not synthesize the missing outer host or QEMU results.
Missing reports fail closed. Automated guest provisioning and collection of
this combined inventory remain operator setup work before release readiness.
The topology change alters the contract digest: regenerate requests, plans,
assessments and case-bound reports; do not reuse earlier native-only results.

Before running the native program, place the reviewed compatibility assessment for
each target at
`/etc/aos-release/qualification-assessments/<target-id>.json`. The file is the
canonical `CompatibilityAssessment` object for the exact environment-profile
digest printed during case review. It must be a regular file rather than a
symlink. The native program supplies the observed inventory; the assessment
does not supply or override test results. Missing or mismatched assessments,
OCI objects, runtime properties, lifecycle operations, or report bindings fail
the case and leave the complete failed attempt in the executor work root.

Completion container claims still consume retained campaign reports because
the `soak` profile's observation window exceeds the executor's six-hour process
bound. Those reports must cover the same target inventory and include
the required operation denominators and committed-data result.

An executor that imports reports from several machines or package exercises can
instead use `--report-root DIR`. The CLI selects
`DIR/<case-digest-without-sha256-prefix>.json` from the exact case in the
request. The report producer obtains that digest from `qualification cases` and
must create a new canonical file for every case; a report for another release,
manifest, publication record, or case is rejected.

The report uses the common fields below and may retain additional
scenario-specific measurements and diagnostics. `checks` must contain every and
only the case's required checks. Release-wide and package reports use an
unscoped, non-sensitive `environment` inventory. Target reports use the typed
environment inventory and reviewed assessment described above. Assessment-only
A1 reports omit `environment`.

```json
{
  "schema_version": "aos.release.qualification-scenario-report/v1",
  "registry": "andyl/experimental",
  "release_id": "release-2026.9.0",
  "staging_receipt_digest": "sha256:<staging-receipt-hash>",
  "manifest_digest": "sha256:<manifest-hash>",
  "case_digest": "sha256:<qualification-case-hash>",
  "started_at": "2026-09-06T18:00:00Z",
  "finished_at": "2026-09-06T18:02:00Z",
  "observed_seconds": 120,
  "checks": {
    "anonymous-download": {
      "passed": true,
      "detail": "Verified the retained public object inventory."
    }
  },
  "operations": {"verified_objects": 3},
  "environment": {"runner": "qualification-host-01"}
}
```

`qualification respond` derives the request, executor, environment, report,
subject, predecessor, authority and nonce bindings. It verifies the report's
registry, release, publication record, manifest, and case identities first. It
also rejects an unknown registry mapping, wrong check set, empty check details,
malformed UTC times, an observation longer than its execution interval, or an
environment shape that does not match the case.

The flake exposes `qualification-executor-<platform>` packages for all four
release platforms under `packages.x86_64-linux`, plus a native
`qualification-executor` alias on each supported system. The `release-tooling`
package bundles the native one with the CLI under
`libexec/aos-release/executors/<platform>/`, where `advance` discovers it and
passes it to `step qualify-run`. Before starting an
executor, install each applicable report-backed scenario's single-link
canonical report at
`/run/aos-release/qualification-reports/<platform>/<case-digest>.json`.
The staging container and native ability lifecycle cases execute directly and
do not read this report directory. Environment recovery exercises are not
executor cases; they are [fitness attestations](qualification.md#fitness-attestations). Each
report-backed adapter
drains the coordinator request, captures the selected report without following
links, and binds it through `qualification respond`. A missing, changing,
stale, malformed, incorrectly identified, or case-incomplete report fails the
attempt.

A fixture gate covers regression behavior only. The native Hub fleet uses
visibly synthetic observations and timing to test the approval mechanics;
those records cannot establish release workload duration or physical
reliability.
The same acceptance conditions govern real automated and operator adapters.
