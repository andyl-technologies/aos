# Release qualification

AOS uses one versioned server contract for testing and production. The
authoritative inputs are [`qualification/`](../../qualification/default.nix).
The release class selects obligations in that contract; operators cannot
remove individual mandatory gates from a release request.

Start with the [release checklist](release-checklist.md), which includes the
manual recovery checks and when to perform them. This page specifies the
contract and evidence formats; the [command reference](canonical-releases.md)
documents command arguments.

## Target support matrix

A target is an architecture and execution environment, such as x86_64 on QEMU
or x86_64 on physical hardware. Its tier defines the release guarantees for
that environment. The release class separately sets observation time and review
requirements; tier assignments apply across all release classes.

### Tier guarantees

| Guarantee | Tier 1: qualified | Tier 2: builds provided | Tier 3: experimental |
| --- | --- | --- | --- |
| Official artifacts | Required for every release | Required; may use the same generic image as a Tier 1 target | No target-specific artifact commitment |
| Hermetic build, signatures, complete closure and source | Required | Required | Required for any artifact actually published |
| Installation and basic operation | Tested on the target for every release | Generic image is tested on its Tier 1 reference; operation on this hardware is not guaranteed | No release qualification guarantee |
| Configuration, packages, networking and workload | All applicable target checks must pass | Target-specific testing is best effort; publish known limitations | Development testing only |
| Update, rollback, recovery and data preservation | Tested on the target with the exact predecessor/candidate pair | No target-specific guarantee | No target-specific guarantee |
| Workload observation | Full release-class window on the target | No target-specific observation requirement | No observation requirement |
| Maintenance | Assigned owner and maintained regression scenarios | Assigned owner for artifact builds and compatibility reports | Contributions accepted; no release-maintenance commitment |
| What blocks release | Missing artifacts, failed or missing qualification, or unresolved required-function/integrity failure | Missing or invalid promised artifacts; a hardware-only failure is documented and does not block unrelated Tier 1 targets | No target-specific blocker; shared defects still block affected higher-tier targets |

All published bytes retain the same integrity requirements at every tier. Known
defects in shared boot, storage, trust or update code must be evaluated against
every affected target.

### Architecture and environment assignments

| Target | x86_64 | aarch64 | Artifact | Scope |
| --- | --- | --- | --- | --- |
| QEMU virtual machine | Tier 1 | Tier 1 | Disk image | UEFI, persistent TPM 2.0, virtio disk/network; x86_64 `q35` with KVM, aarch64 `virt` with TCG functional coverage |
| OCI container on native Linux | Tier 1 | Tier 1 | OCI image and multi-platform index | AOS-built containerd/runc; matching host/image architecture; persistent volumes and network workload |
| Physical server | Tier 2 | Unassigned | Generic disk image | x86_64 server hardware meeting the boot/storage requirements below |
| Physical workstation | Tier 2 | Unassigned | Generic disk image | x86_64 workstation hardware; headless OS operation |
| Cloud virtual machine | Tier 3 | Tier 3 | Generic disk image where importable | Provider image import, firmware, virtual devices and metadata compatibility require environment-specific validation |

Unassigned targets carry no support commitment. Hardware and cloud requirements
are expressed in terms of boot, storage, network and provisioning capabilities.
Qualification reports retain equipment inventories and firmware versions so
coverage can be reproduced and reviewed.

Release approval requires evidence satisfying the assigned tiers and resolution
of the [current release blockers](release-checklist.md). An unavailable Tier 1
runner or scenario blocks qualification; it does not change the target's tier.

`qualification/targets.nix` encodes those four Tier 1 configurations as required
cases. Tier 2 physical targets consume the same frozen generic images; the build
and artifact checks apply, but physical qualification is not presently a required
case. Tier 3 has no additional required target case.

### Changing a target's tier

A tier change requires a reviewed policy change before freezing a release.
To enter Tier 2, identify an owner, the exact official artifact and its automated
build/integrity checks, and document hardware requirements and known limitations.
To enter Tier 1, also add required target configurations and maintained scenarios,
pass every applicable acceptance check below, and complete the class observation
window on representative equipment. Record that evidence with the release that
first carries the stronger guarantee. Downgrading a target requires an explicit
support notice; it cannot be an operator workaround for a failed required case.

Record exact runtime versions, host kernel, firmware, CPU, devices, image digests
and test-program identity in qualification evidence. TCG qualification covers
functional behavior; native KVM and performance claims need separate evidence.

### Images, packages and optional hardware features

The target tier covers the base OS or container contract and its required
workloads. Each advertised disk format must pass artifact-equivalence checks.
Cloud-provider compatibility requires separate environment qualification.
Each published package/platform cell needs the functional checks below;
package roles add obligations according to their effect on the system.

Record optional features such as redundant storage, GPU acceleration, hardware
watchdogs and server management separately, with their tested capability scope
and limitations. Missing package or feature evidence blocks its qualification.
Stable and emergency releases prohibit blocked package/platform cells under
the shared contract.

### QEMU and disk-image acceptance

Apply these checks to each published image variant on each required configuration.
Use its public signed bytes and supported provisioning path. The current VM
test configuration is 2 vCPUs, 8 GiB RAM and a 32 GiB disk. Minimum system
requirements require a separate resource-sizing campaign.

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

Physical targets require UEFI, Secure Boot, persistent TPM 2.0, supported
storage/network drivers, and a console/recovery path. Record capability
requirements and known exclusions in the support record. The base contract
covers headless operation; graphical desktop, GPU acceleration and suspend
require separate feature qualification.

Tier 1 qualification requires disk-image checks on representative server and
workstation equipment covering Intel and AMD CPUs, onboard and discrete NICs,
SATA and NVMe storage, and different UEFI implementations. Retain models and
firmware versions in the test inventory. Add uncovered capabilities to the
campaign or exclude them explicitly from the qualified scope.

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
families covering those capabilities and retain the environment inventory.
Unsupported boot/security features require a reviewed contract change.

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
