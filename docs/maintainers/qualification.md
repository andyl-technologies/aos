# Release qualification

AOS uses one versioned server contract for testing and production. The
authoritative inputs are [`qualification/`](../../qualification/default.nix).
The release class selects obligations in that contract; operators cannot
remove individual mandatory gates from a release request.

Start with the [release checklist](release-checklist.md), which includes the
manual recovery checks and when to perform them. This page specifies the
contract and evidence formats; the [command reference](canonical-releases.md)
documents command arguments.

## Support levels and target checks

Support scope answers where an artifact must work. Release class answers how
long it is observed and who approves it. Testing releases still need working
install, update, recovery, and workload behavior on the required runtimes.

| Runtime or hardware category | Architecture | Priority and required coverage |
| --- | --- | --- |
| QEMU VM, `q35`, UEFI, virtio disk/network, persistent TPM 2.0 | x86_64 | Required now; KVM boot, lifecycle, update/recovery, workload and soak checks |
| QEMU VM, `virt`, UEFI, virtio disk/network, persistent TPM 2.0 | aarch64 | Required now; same functional checks under TCG; native KVM support needs its own evidence |
| OCI containers using containerd/runc on native Linux | x86_64 | Required now; signed OCI selection, pull, lifecycle, network, volumes and soak checks |
| OCI containers using containerd/runc on native Linux | aarch64 | Required now; same container checks on a native aarch64 host |
| Physical servers and workstations | x86_64 | Next; general hardware support using representative equipment and the physical checks below |
| Cloud VMs | x86_64 and aarch64 | After physical hardware; image lifecycle plus cloud provisioning, storage and recovery checks below |

These are requirements and rollout priorities, not claims of completed testing.
The current machine-readable contract requires the four QEMU/container rows.
Physical and cloud rows are planned. Before advertising either as supported,
add required configurations to `qualification/targets.nix`, implement their
scenarios, and pass them in the frozen release. The recorded configurations
describe the coverage used to justify a category; they are not a model allowlist.
The target schema supports additional configurations, but those scenarios and
their capability coverage still need implementation.

For each row and package/platform cell, record one of these levels:

| Level | Required evidence | Release decision |
| --- | --- | --- |
| Planned | Scope, missing work and owner recorded | No support claim; does not block until made required |
| Preview | Authentic published artifacts, meaningful basic functional checks, explicit unqualified behaviors | Allowed only outside the required baseline; cannot hide failure of an advertised basic function |
| Supported for this release class | All applicable checks below, class observation window and required review passed | Failure or missing evidence blocks release for a required/supported row |
| Blocked | Failure or missing prerequisite recorded with affected artifacts | Do not publish the affected artifact as usable; stable/emergency permit no blocked package/platform cells |
| Not applicable | Recorded architectural or product-scope reason | Cannot be used for an unavailable runner, failed build or one of the four required runtimes |

Maintain this table in the release record before generating the plan. The
planned/preview labels are planning and communication states; they do not waive
the plan's required cases or create a separate CLI support-status control.
Passing on one architecture, runtime, release, or package cannot check off another.
Record exact QEMU/containerd/runc versions, host kernel, firmware, CPU, device inventory,
image/index digests and test-program identity. Emulation can establish the stated
TCG functional result; it does not establish native acceleration or performance.
Docker Engine is not a separate qualification prerequisite. Record any untested
frontend or host-specific behavior instead of extending the runtime results to it.

### QEMU and disk-image acceptance

Apply these checks to each published image variant on each required configuration.
Use its public signed bytes and supported provisioning path. The current VM
baseline is 2 vCPUs, 8 GiB RAM and a 32 GiB disk; that is a tested configuration,
not a demonstrated minimum system requirement.

| Test | Pass condition |
| --- | --- |
| Download and install | Anonymous download resumes after interruption; signatures, size and digest verify; every advertised disk format reconstructs the same raw image; a clean disk provisions successfully without fixture keys |
| Boot | 10 consecutive clean reboots and 3 full VM stop/start cycles succeed without repair; persistent firmware and TPM state survive; each boot reports the intended image identity and required services healthy |
| Host configuration | Create a user and SSH key, set hostname, DNS and time source, and exercise DHCP and static addressing; authenticate over SSH and verify resolution/time synchronization after reboot; activate and roll back a configuration with the expected identity |
| Boot and storage integrity | Valid boot and encrypted-state unlock succeed; modified boot/root data and unauthorized keys are rejected; the documented recovery path works without bypassing the release trust policy |
| Update and rollback | Complete 3 predecessor-to-candidate update/rollback cycles; verify boot blessing, selected image, configuration binding and retained generations at each transition |
| Interrupted update and recovery | Interrupt at each updater commit boundary exposed by the scenario, including before/after boot selection; every attempt boots the committed image or documented fallback; explicit rollback and offline recovery work, followed by another successful update |
| Persistent workload | Serve a known response with nginx over HTTP and TLS; reject an invalid certificate from the client; append numbered durable records and verify their hashes after reboot, update, rollback and recovery |
| Resource exhaustion | Exercise full state/update storage and memory pressure in the isolated test; mutation fails with a useful error, committed state remains readable, and operation succeeds after resources are restored |
| Observation | Run mixed network, package and persistent-data operations for the release-class window; retain attempts, successes, failures, reboot/recovery counts and monitoring records; no unexplained crash, integrity mismatch, data loss or unresolved required-function failure |

The cycle minima are encoded in target configuration and bound into each case.
They are engineering acceptance thresholds, not reliability probabilities.
Scenario reports must show the counts and comparisons, not just a success flag.

### OCI-container acceptance

Run these checks with AOS-built containerd/runc on both native Linux architectures.
Record the runtime versions and host configuration in the environment inventory.
Existing fleet tests provide regression coverage; the same checks against the
exact published artifacts are required before a public release can pass this gate.

| Test | Pass condition |
| --- | --- |
| Pull and platform selection | A clean client anonymously pulls by the release's immutable digest; the signed index selects the correct architecture; selected manifest/config/layer digests match the release; no emulation is needed |
| Documented launch | The published run command starts the declared workload with only its documented user, mounts, capabilities and privileges; readiness and HTTP/TLS checks pass; no undeclared privileged mode or host access is added to make the test pass |
| Network | Published ports and container DNS work; restart/recreation does not leave stale connectivity; traffic reaches the intended container |
| Lifecycle and state | Complete 10 stop/start/recreate cycles using a named volume; each graceful stop respects the documented timeout and exit behavior; numbered committed records and hashes survive removal/recreation; an abrupt kill preserves records already acknowledged as durable |
| Limits and signals | Runtime CPU/memory limits are applied and observed; the workload handles its documented termination signal; memory exhaustion has the documented failure/restart behavior without corrupting committed volume data |
| Image replacement | Recreate with the candidate digest using the existing volume, then exercise the documented recovery/rollback path; verify data compatibility rather than assuming image rollback reverses data migrations |
| Profile and observation | Verify the testing/production registry and trust identities, run the persistent network workload for the class window, and retain operation counts and failures with no unresolved required-function or integrity failure |

### Physical-hardware acceptance

The intended support category is **x86_64 servers and workstations**, not a list
of approved models. Initially the image's boot/security contract requires UEFI,
Secure Boot, persistent TPM 2.0, supported storage/network drivers, and a working
console/recovery path. State capability requirements and known exclusions in the
support record; a machine's marketing category alone does not establish those
capabilities. Workstation hardware runs the same headless server contract here;
graphical desktop, GPU acceleration and suspend are additional feature claims.

Before promoting this category, run the disk-image checks on representative
server and workstation equipment. Cover both Intel and AMD CPUs, onboard and
discrete NICs, SATA and NVMe storage, and different UEFI implementations across
the sample. Record models and firmware for reproducibility, without restricting
support to those models. Any uncovered capability must be added to the test
campaign or explicitly excluded from the initial supported scope.

In addition, verify installer media boots, disks/NICs enumerate correctly,
storage read/write checksums agree under load, link loss/reconnection recovers,
and shutdown powers off. Perform the 3 cold boots by removing/restoring power;
exercise interrupted writes only on expendable test storage. Monitor machine
checks, storage errors and thermal behavior during the class soak; unexplained
hardware/driver faults block promotion pending diagnosis. Requalify affected
coverage after kernel, driver, firmware or boot/security changes.

### Cloud-VM acceptance

Promote x86_64 and aarch64 cloud support separately. For each advertised cloud
environment, record image import format, boot/security capabilities, virtual
storage/NIC drivers and provisioning interface. Test representative instance
families covering those capabilities; individual VM identities are evidence,
not a permanent list of supported instances. Unsupported boot/security features
need an explicit reviewed contract change, not an unrecorded test exception.

Pass the disk-image checks plus image import, clean instance creation, metadata
and SSH-key provisioning, DNS and time synchronization, persistent-volume
reattachment, stop/start, and replacement from the retained image. Verify data
hashes after volume recovery, reject access to another tenant's credentials or
state, and demonstrate the provider-console recovery path. Record ephemeral
disk behavior explicitly. A local QEMU pass does not check off these operations.

### Software-package acceptance

Every published package/platform cell needs an anonymous install from the
release, closure/signature verification and a functional test. Run it on the
target architecture. A successful build, import or `--version` alone is insufficient.

| Package role | Concrete checks |
| --- | --- |
| All packages | Exercise a documented primary operation with a known expected result; cover a bad input/error path; install/change/remove through the supported package workflow and recover its generation; verify declared dependencies, permissions and absence of undeclared host tools |
| Libraries | Compile/link and run a small public-API consumer with checked output; for header-only/static libraries compile the consumer; test a dependent application where the library has a runtime role |
| Build tools | Compile or transform a representative input and execute/inspect the result; verify reproducibility where promised, not merely that the tool starts |
| System integrity | In addition to the package test, pass dependent boot, authentication, signature rejection, configuration, update and recovery cases; shell/coreutils run scripts, OpenSSH authenticates and rejects unauthorized keys, OpenSSL verifies valid and rejects invalid chains, chrony synchronizes, filesystem/cryptographic tools preserve and recover test data |
| Qualified workloads | nginx serves known HTTP/TLS responses and persists workload state; containerd/runc start, network, stop and recover their declared workloads; exercise limits and error paths as well as the happy path |
| General catalog | Record package-specific input, command/API, expected output and observed result; declaring the role is not a functional-test exemption |

Dependencies inherit the obligations of the integrity/workload roots using
them. Record package-specific feature exclusions before the plan is frozen;
do not disable features to simplify the build or label a broken basic operation
as preview. Existing non-Linux package eligibility remains separate from Linux
OS/runtime support and still requires its own native package tests.

## Inspect and freeze the contract

```sh
aos release contract --class edge --output qualification-contract.json
aos --json release contract --class edge
aos release contract --class stable --input qualification-contract.json
```

The output lists requirements, never claims that they passed. JSON output
contains the exact `gates` and `public_evidence_policy_digest` for the reviewed
plan request. `--output` writes a new canonical file and refuses replacement.
`--input` supports inspection without Nix or network. New plans use
`aos.release.plan/v2` and embed the complete contract; older v1 bundles remain
readable for archival verification.

Record a `qualification_predecessor` with the same registry, a distinct
`release_id`, and the verified preceding `manifest_digest`. First public
releases use a retained signed qualification snapshot as their predecessor.
A testing-to-main transition is a new main release and installation unless a
separate authenticated migration contract has been implemented and qualified.

## Shared obligations

| Obligation | Edge/testing | Candidate | Stable/emergency |
| --- | --- | --- | --- |
| Authentic artifacts, complete closures, source/license evidence | Required | Required | Required |
| Both reference Linux disk and OCI environments | Required | Required | Required |
| Declared install, configure, package, update, recovery workflows | Required | Required | Required |
| Blocked additional package/platform cells | Explicitly permitted | Explicitly permitted for incomplete candidates | Forbidden |
| Mixed-workload observation | 24 hours | 7 days | 14 days |
| Independent review and production recovery | Recorded testing arrangement | Required | Required |
| Operational exercise age | At most 30 days | At most 30 days | At most 30 days |

Durations are engineering policy, not statistical failure-rate claims. Record
machines, workload, attempts, successes, failures, and recovery operations.
Emergency is not a switch that removes integrity or recovery requirements.
Changing its observation rule requires a reviewed policy revision first.

## Requirements, subjects, and evidence

Each requirement specifies its hold point, subject population, observation
method, acceptance checks, regression coverage, and invalidation conditions.
The coordinator expands requirements into exact cases:

- release-wide gates cover the frozen release artifacts;
- package gates cover each published package/platform cell independently;
- image gates cover each variant and reference machine configuration;
- OCI gates cover the multi-platform index and exact platform artifacts; and
- update cases additionally bind the frozen preceding release.

The case digest binds these choices, the frozen plan, and the complete artifact
records (including byte digests and sizes). Reusing logical artifact names
cannot reuse an observation for changed bytes. An observation records each acceptance
condition, immutable executor identity, actual environment identity, execution
times, operation counts, and the predecessor exercised. Missing, failed,
unknown, duplicated, future-dated, expired, or incorrectly scoped evidence
cannot satisfy a required case. Preserve failed attempts; a later pass does not
erase them from the operational record.

Build observations belong in the immutable manifest. Staging observations
refer to that finished manifest and its staging receipt. Rollout and completion
observations are later records; never mutate the original manifest to add
evidence that did not exist when it was signed.

## Collect, review, and sign

Inspect the actual case population before allocating machines:

```sh
aos release qualification cases --plan release-bundle/release-plan.json \
  --manifest release-bundle/release-manifest.json --phase staging
```

This command displays requirements; it does not verify signatures or claim a
pass. Use `aos release verify` with independent public anchors for verification.

Run `aos release qualify-run --prepare-only` with the bundle, publication
receipt, applicable executor mappings, and `--qualified-at now` described in
[the runbook](canonical-releases.md#run-the-native-qualification-matrix).
Inspect the prepared report and its retained `reports/` directory. Sign an
independent review payload with a planned `release-evidence` key:

```json
{
  "schema_version": "aos.release.qualification-review/v1",
  "plan_digest": "sha256:<canonical-plan-hash>",
  "report_digest": "sha256:<exact-prepared-report-hash>",
  "authority_id": "<planned-reviewer-key-id>",
  "accepted": true
}
```

Use the existing signed-receipt envelope: Ed25519 signs the SHA-256 of
`aos.hub.release-evidence-signature/v1`, a NUL byte, then the canonical payload.
This is `RECEIPT_SIGNATURE_DOMAIN` in `crates/aos-release/src/receipt.rs`.
Keep review signing under the configured authority provider, outside the Nix
store. Review thresholds are required for candidate, stable, and emergency.
Testing may include reviews voluntarily. Human independence and custody are
confirmed in the maintainer checklist; separate key IDs alone do not prove it.

Repeat `qualify-run` with `--report-input PREPARED/qualification-report.json`
and each `--review-receipt PATH`, omitting `--prepare-only`. The authority checks
and signs the same report. Its output atomically retains report bodies,
reviews, and signatures. Keep that entire directory and the separately retained
`.aos-qualification-attempt-*` directories. `qualify` and `promote` recheck the
original report directory, including its bodies and reviews; a copied aggregate
JSON file alone is insufficient.

For rollout use `--phase rollout --publication-receipt PRODUCTION_RECEIPT`
(the latter aliases `--staging-receipt`), the production Hub receipt key,
`--journal CURRENT_JOURNAL`, and `--rollout-intent NEXT_RANGE.json`:

```json
{"channel":"edge","first_partition":0,"last_partition":31,"prior_generation":0}
```

For completion use `--phase complete` with the current production receipt and
rolling journal. No rollout intent is supplied. These authority signatures
bind the exact report, policy, manifest, publication receipt, entire journal,
and next range where applicable. Channel commands require `--qualification`
and `--qualification-key`; observations and approvals at rollout must be at
most ten minutes old. Recollect health for each new range. A completion
approval must also be fresh, while its workload report covers the full selected
observation window. Campaigns lasting days run outside a single bounded RPC;
import their retained observations for review and admission.

## Native executors

`lib.testing.mkQualificationExecutor` (from `lib/testing`) packages a runner
with explicit `platform`, `identity`, `scenarios`, absolute `workRoot`, and
`timeoutSeconds`. `scenarios` maps requirement IDs to absolute executables in
AOS-built Nix closures. Missing implementations fail; an empty adapter is never
a passing gate. Environment-specific adapters and remote macOS transport must
be provisioned before a campaign. All source regression groups are exposed at
`checks.qualification.<requirement-id>` and `checks.qualification.all`.

The runner reads a canonical v2 executor request on stdin. It verifies every
anonymous HTTPS download's size and SHA-256, retains it under a hashed name,
and writes `request.json`, `scenario-registry.json`, and `objects.json` in a
private attempt directory. The configured scenario receives the request on
stdin and runs in that directory with no inherited environment. `objects.json`
maps artifact IDs to the verified local paths. Scenarios use AOS-built tools
and the published image's normal provisioning and serial/SSH interfaces.

The scenario emits `QualificationExecutorResponseV1`. Its observation must
contain the exact case digest, acceptance checks, and predecessor. Set
`executor_digest` to the SHA-256 of the retained scenario registry bytes;
its store paths bind the executable closures. Include the actual non-sensitive
environment inventory in `report.environment`, and set `environment_digest`
to its canonical JSON SHA-256. Record real UTC times and measured workload
counts. The runner checks this binding and retains response bytes, stdout,
stderr, and failures. Coordinator attempts retain each request and returned
response, including rejected results. Never overwrite a failed attempt.

A fixture gate proves regression behavior only. The native Hub fleet uses
visibly synthetic observations and timing to test admission mechanics; those
records cannot establish release workload duration or physical reliability.
The same acceptance conditions govern real automated and operator adapters.

## Qualification roles and public status

Package roles describe consequences: `system-integrity`, `qualified-workload`,
or `general-catalog`. Dependencies inherit the obligations of the root that
uses them. The authenticated runtime closure is the source of dependency
membership. A library used by boot or recovery cannot avoid those tests by
being listed as a general catalog package.

Public status is separate: qualified for testing, preview, blocked, or not
applicable. A reference target in the contract is a requirement, not a passing
hardware claim. Publication integrity applies equally to preview packages.
Known failure of an advertised basic function blocks that artifact. Successful
builds and `--version` checks do not establish complete functionality.

## Test execution and reuse

Nix derivations own hermetic evaluation, build, and fixture/fleet regression
tests. Nix-packaged executors own fresh public-download and live-environment
qualification. Physical equipment and operator observations use the same
acceptance/evidence model. Do not put deployment credentials or private
attestations in Nix inputs, the store, or public reports.

The existing fleet tests may add agents or controlled fault hooks. Their
results describe those fixtures. Exact-artifact qualification boots the
published immutable image using its supported provisioning and serial/SSH
interfaces; it must not rebuild the image to insert a test agent.

Run the pure policy check with:

```sh
nix-build -A checks.qualification.policy --no-out-link
```

The Rust policy fixture is generated by evaluating `qualification/default.nix`
with package names `aos`, `nginx`, `containerd`, and `runc`. The Nix check compares
that fixture with the authoritative data so schema tests cannot drift silently.

Evidence is reusable only for unchanged subjects, policy, executor, and
environment under its age limit. New update pairs need new transition evidence.
Firmware, kernel, bootloader, initrd, storage, updater, and harness changes
invalidate dependent results. Live Hub health always needs a fresh observation.
Uncertain impact selects the broader campaign.

## Policy changes and standards

Review contract changes as release-authority changes. Preserve historical
policy bytes with each release. Requirements use stable IDs; a semantic change
changes the policy digest. Unknown schemas fail closed. Keep identifiers for
truly inapplicable package targets distinct from required but blocked work.

The design borrows assurance-case structure from ISO/IEC/IEEE 15026-2,
quality categories from ISO/IEC 25010, and traceability, failure analysis,
controlled change, and verification practices from security and dependability
engineering. These are engineering references, not claims of EAL, SIL,
DO-178C certification, or full standards conformance.
