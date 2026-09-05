# Release qualification

AOS uses one versioned system contract for testing and production. The
authoritative inputs are [`qualification/`](../../qualification/default.nix).
The release class selects obligations in that contract; operators cannot
remove individual mandatory gates from a release request.

Start with the [release checklist](release-checklist.md), which includes the
manual recovery checks and when to perform them. This page specifies the
contract and evidence formats; the [command reference](canonical-releases.md)
documents command arguments.

## Target support matrix

The support matrix records compatibility claims and the evidence supporting them.
Each claim identifies an artifact, a function, an environment scope, and an
assurance level. Release policy specifies the minimum assurance required for
selected claims. The release class sets observation duration and review obligations.

### Assurance levels

| Level | Evidence required | Permitted claim |
| --- | --- | --- |
| A0: unassessed | No accepted compatibility assessment or applicable execution evidence | Compatibility is unknown |
| A1: assessed | Reviewed CPU/ABI requirements, firmware and device interfaces, enabled kernel drivers, required firmware, and known exclusions | Expected to work within the documented compatibility scope; no direct execution claim |
| A2: exercised | A1 assessment plus direct tests of the exact artifact and stated functions on recorded configurations, with expected and observed results | The listed functions passed on the tested configurations |
| A3: qualified | A2 evidence plus all applicable acceptance checks, update/recovery transitions, release-class observation and required review | The complete stated contract passed qualification on the tested configurations |

Levels express evidence strength, not statistical reliability or certification.
Successful artifact builds establish availability, but do not establish A1
hardware compatibility by themselves. Failed checks, expired evidence and known
incompatibilities are recorded separately from assurance; none may be hidden by
assigning a lower level. Published artifacts always require signatures, complete
closures and corresponding source, regardless of hardware assurance.
Mark a known failing scope incompatible even if historical evidence reached A3.

A2 and A3 apply to the recorded configuration set. A broader compatibility claim
requires its own A1 assessment. For example, a reviewed CPU-family claim may be
A1 while a subset of specific CPU SKUs and platform configurations is A3. The
family retains A1 outside that tested subset. A CPU result alone does not qualify
a motherboard, NIC, storage controller or their combined installation.

### Qualification axes

Use one row for each distinct claim and scope. Multiple rows may cover the same
architecture at different assurance levels.

| Axis | Required scope and evidence fields |
| --- | --- |
| Artifact and function | Release/manifest and image or package digest, variant, kernel build and configuration digest, claimed functions, exclusions, predecessor for update claims |
| Architecture and CPU | x86_64 or aarch64; ISA baseline and required features; vendor, family/model/stepping or implementer/part/revision; exact CPU SKU and microcode/firmware revision when observable |
| Physical platform | Board/system and chipset or SoC, firmware version, boot mode, Secure Boot and TPM configuration, memory topology, relevant buses and controllers |
| Devices and drivers | Device vendor/product/revision IDs, controller and device firmware, bound Linux driver, relevant kernel configuration, module/built-in status, required firmware availability and boot-stage availability |
| QEMU | QEMU version, machine type and version, guest CPU model/features, virtual devices and firmware; accelerator recorded separately as TCG or KVM; for KVM, host CPU, kernel and KVM configuration |
| Cloud | Provider, service, region/zone, instance family and exact SKU, architecture and exposed CPU features, image import format, boot/security options, storage and NIC types, metadata/provisioning interface |
| Container | Host architecture/CPU and kernel configuration, containerd/runc versions, cgroup mode, security settings, network and volume implementation, resource limits |

Record unavailable provider-managed details as unknown, with the provider's
exposed interface or compatibility guarantee as the scope boundary. Unknown
values are not wildcards. Replacing TCG with KVM, changing a cloud SKU, or using
a different NIC creates a distinct configuration even when the architecture
and image are unchanged.

### Required release coverage

The following matrix specifies minimum assurance, not achieved results. Retain
the actual tested configurations and evidence separately for each release.

| Environment | Architecture | Accelerator/runtime | Minimum assurance | Required configuration |
| --- | --- | --- | --- | --- |
| QEMU | x86_64 | KVM | A3 | `disk-x86_64-linux`: `q35`, persistent UEFI/TPM, virtio disk/NIC; record host and guest CPU identities |
| QEMU | aarch64 | TCG | A3, functional contract | `disk-aarch64-linux`: `virt`, persistent UEFI/TPM, virtio disk/NIC; record emulated CPU model/features |
| OCI container | x86_64 | containerd/runc, native host | A3 | `container-x86_64-linux`: persistent network workload and recorded host configuration |
| OCI container | aarch64 | containerd/runc, native host | A3 | `container-aarch64-linux`: persistent network workload and recorded host configuration |
| QEMU | x86_64 / aarch64 | Other architecture/accelerator combinations | Set per additional claim | Separate machine/CPU/device configuration and evidence |
| Physical hardware | x86_64 / aarch64 | Native | Set per claim | CPU SKU set, chipset/SoC, firmware, device/driver combinations |
| Cloud VM | x86_64 / aarch64 | Provider virtualization | Set per claim | Provider/service, exact instance SKU, region and virtual device profile |

[`qualification/modules/qemu.nix`](../../qualification/modules/qemu.nix) and
[`containers.nix`](../../qualification/modules/containers.nix) define the four
mandatory reference configurations.
Their required checks cannot be waived by lowering assurance. Additional claims
must state their required level and release-blocking status before the plan is
frozen. Additional A3 image/container claims require corresponding target cases
and scenarios. Physical or cloud categories receive no blanket assurance from
the reference VM results.

Each required target has a release-blocking A2 claim at staging and an A3 claim
at completion. A3 requires the complete functional and recovery checks and the
class observation window on that same recorded configuration. Staging evidence
does not award A3 before observation completes.

A2 and A3 outcomes cover the exact inventory identified by their environment
digest. Declare separate required targets for the CPU, board, device and runtime
combinations that must each be exercised. A target's compatibility predicates
define which configurations may satisfy its case.

### Release evidence matrix

Retain this matrix with the release records and include the approved claims in
release support information. Every row must contain:

| Field | Required value |
| --- | --- |
| Claim | Stable identifier and specific function or contract, such as installation, network operation, or complete image lifecycle |
| Compatibility scope | Explicit architecture, CPU/features, platform and device predicates; runtime/accelerator or provider/SKU where applicable |
| Tested configurations | Inventory IDs for the exact combinations exercised; an empty set for assessment-only claims |
| Required assurance | A1, A2 or A3, plus whether failing this obligation blocks release |
| Achieved assurance and result | Highest currently supported level; pass, fail, missing or stale evidence; known incompatibilities |
| Evidence | Artifact/plan/case digests, assessment references, test reports, dates, operation counts, observation window and reviewer |
| Maintenance | Owner, evidence expiry and changes that invalidate the claim |

The matrix is a reviewed release record. Required executor cases and signed
reports remain the admission mechanism; matrix entries cannot replace missing
observations or change a frozen gate. Before approval, reconcile every mandatory
case with its matrix row and inspect the retained environment inventories.

### Coverage and generalization

Select test configurations by meaningful variation: CPU generation and features,
chipset/SoC, firmware implementation, storage/NIC controller and driver, runtime
backend, and cloud device profile. Document which dimensions each configuration
covers. Separate component passes do not establish the Cartesian product of all
CPU, board and device combinations; retain complete tested configurations and
review the remaining combinations as A1 compatibility claims.

A driver present in Linux source is insufficient for an A1 claim. Verify that the
released kernel enables the driver, supports the device ID, contains required
firmware, and makes the driver available at the stage that needs it. A2 requires
observing driver binding and exercising the device. A3 requires its applicable
load, interruption and recovery checks as part of the claimed system contract.

Reassess claims after changes to artifacts, kernel configuration, CPU feature
baseline, firmware, drivers, QEMU machine/CPU model, accelerator, runtime or cloud
profile. Preserve historical results, mark invalidated evidence stale, and obtain
fresh evidence before retaining the affected assurance claim. A shared defect
blocks every release obligation whose scope includes it.

### Images, packages and optional hardware features

Image lifecycle, individual devices, optional features and package/platform cells
may carry separate claims. Each advertised disk format requires equivalence
verification; provider import is a separate cloud claim. Every published package
needs the functional checks below, with additional obligations inherited from its
system-integrity or workload role.

Record optional features such as redundant storage, GPU acceleration, watchdogs
and server management with their own functions, configuration scope and evidence.
An A3 base-image result covers only the features included in that contract.
Stable and emergency releases prohibit blocked package/platform cells under the
shared contract.

### QEMU and disk-image acceptance

Apply these checks to each A3 image-lifecycle claim and required configuration.
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

The cycle minima are numeric requirement bounds, composed by the image and
container modules and bound into each case.
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

Physical image-lifecycle claims require UEFI, Secure Boot, persistent TPM 2.0,
supported storage/network drivers, and a console/recovery path. Record capability
requirements and known exclusions in the support record. The base contract
covers headless operation; graphical desktop, GPU acceleration and suspend
require separate feature qualification.

A3 physical-image qualification requires the disk-image checks on each selected
configuration. Choose CPU SKU, chipset/SoC, firmware and device combinations to
cover the claim's scope. Record CPU identities, board revisions, PCI/USB device
IDs, bound drivers and firmware versions. Verify storage and network drivers are
enabled in the released kernel and available during installation and recovery.
Untested combinations remain subject to their separate compatibility assessment.

In addition, verify installer media boots, disks/NICs enumerate correctly,
storage read/write checksums agree under load, link loss/reconnection recovers,
and shutdown powers off. Perform the 3 cold boots by removing/restoring power;
exercise interrupted writes only on expendable test storage. Monitor machine
checks, storage errors and thermal behavior during the class soak; unexplained
hardware/driver faults block the affected qualification pending diagnosis.
Requalify affected coverage after kernel, driver, firmware or boot/security changes.

### Cloud-VM acceptance

Qualify each cloud claim against its provider, service, exact instance SKU,
architecture, region and device profile. Record image import format,
boot/security capabilities, exposed CPU features, storage/NIC drivers and
provisioning interface. Retain each tested configuration in the environment
inventory; family-wide compatibility requires a separate assessment.
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

The qualification catalog uses the AOS `lib.evalModules` fixed point. Feature
modules under `qualification/modules/` own their options, configuration and
assertions. The module registry discovers feature files automatically and
excludes `_`-prefixed implementation files. `qualification/default.nix` accepts
additional `modules`; normal `mkDefault`, `mkForce`, `mkIf`, `mkMerge` and list
ordering rules apply. Required acceptance floors still constrain the result.
Package classifications and target claims derive from the final configuration.

Each requirement specifies its hold point, subject population, observation
method, acceptance checks, numeric bounds, regression coverage, and invalidation conditions.
The coordinator expands requirements into exact cases:

- release-wide gates cover the frozen release artifacts;
- package gates cover each published package/platform cell independently;
- image claims cover each variant and their declared target configuration;
- OCI claims cover the multi-platform index and exact platform artifacts; and
- update cases additionally bind the frozen preceding release.

The case digest binds these choices, the frozen plan, and the complete artifact
records (including byte digests and sizes). Reusing logical artifact names
cannot reuse an observation for changed bytes. An observation records each acceptance
condition, immutable executor identity, actual environment identity, execution
times, operation counts, and the predecessor exercised. Missing, failed,
unknown, duplicated, future-dated, expired, or incorrectly scoped evidence
cannot satisfy a required case. Preserve failed attempts; a later pass does not
erase them from the operational record.

Current plans embed `aos.release.qualification-contract/v2`; current cases use
`aos.release.qualification-case/v2`. Every target observation includes a reviewed
assessment bound to the canonical environment-profile digest. A1 contains the
reviewer's rationale and exact retained references, without execution times or
operation counts. A2 and A3 additionally contain a typed
`aos.release.environment-inventory/v1` document. The coordinator verifies its
digest and matches the ordered host-to-subject topology, CPU predicates, backend
versions, boot implementation, security properties, resources and device bindings.
An environment digest alone cannot establish compatibility.

Finalized images publish `aos.image.metadata/v2` with an
`aos.image.capabilities/v1` inventory. The Nix assembly captures the built
kernel's resolved configuration; the finalizer inventories signed module bytes
and firmware from the runtime, normal initrd and both recovery filesystems.
Built-in drivers come from that kernel's `modules.builtin`. Image observations
retain the complete metadata value and its subject artifact ID. The coordinator
checks its size and hash against the manifest, verifies required configuration
values and driver/firmware availability at the required stages, and binds direct
execution to the same capability digest. Build availability and observed device
binding are separate requirements.

`aos.release.qualification-report/v3` records coordinator-derived claim outcomes
alongside the observations. Consumers recompute those outcomes; an executor
cannot assign its own assurance. Missing, failed and stale optional claims remain
visible and do not block admission. Malformed or incorrectly bound evidence is
rejected even for an optional claim. A complete functional run with insufficient
observation duration can establish A2 but cannot satisfy an A3 obligation. Reports
require the configured authority signatures and independent review before they
authorize release operations. Archived v1 contracts retain their original digest
semantics and cannot authorize new publication.

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
`timeoutSeconds`. `scenarios` maps case policy IDs, including `claim-<claim-id>`, to absolute executables in
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
contain the exact case digest, acceptance checks, numeric measurements, assessment
and applicable environment/capability evidence. Include the predecessor for update
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
