# Release qualification

AOS uses one versioned system contract for experimental and production. The
authoritative inputs are [`qualification/`](../../qualification/default.nix).
A release is published to one or more **destinations**. Each destination
selects a named **profile**, and the profile states everything the release
must prove before that destination may be published: gates, selected claims,
soak, review, matrix completeness, environment fitness, and rollout rings.
Operators cannot remove individual gates from a plan; the only permitted
relaxation is a signed [profile override](#profile-overrides) of the fields a
profile marks overridable.

Environment recovery is not proven per release. Backup restore, authority
recovery, Hub restore, key rotation, and alert delivery are **fitness
exercises** performed on their own cadence. Each produces a signed, dated
[fitness attestation](#fitness-attestations) bound to the identities it
covered, and a profile requires attestations no older than its stated maximum
age.

Start with the [release checklist](release-checklist.md), which gives the order
of operations and the fitness exercise cadence. This page specifies the
contract and evidence formats; the [command reference](canonical-releases.md)
documents command arguments.

## Destinations and profiles

### Surfaces and destinations

An unpublished **release stage** is an exact candidate id, revision, and
artifact inventory; it is independent of the deployment named staging. See
[release stages](../registry/release-stages.md).

A **surface** is one publication endpoint with the role `staging` or
`production`. It is either an AOS Hub deployment or a
[static origin](#static-surfaces). A **destination** is one surface role and
one channel of the plan's registry, written `<role>/<channel>`. The registry
comes from the plan, so `production/edge` in an `andyl/main` plan and
`production/edge` in an `andyl/experimental` plan are distinct destinations on
different registries.

The contract exports exactly these destinations. Anything else is not a
destination, and plan validation rejects it.

| Destination | Registry tier | Profile | Published after |
| --- | --- | --- | --- |
| `staging/edge` | production (`andyl/main`) and experimental (`andyl/experimental`, `andyl/experimental-vN`) | `build` | nothing |
| `production/edge` | production and experimental | `smoke` | a staging publication |
| `staging/candidate` | production | `build` | nothing |
| `production/candidate` | production | `functional` | a staging publication |
| `staging/stable` | production | `build` | nothing |
| `production/stable` | production | `soak` | a staging publication |

`andyl/main` carries `edge`, `candidate`, and `stable`. Experimental registries
carry the `edge` channel only. A channel kind selects the same profile on every
tier that carries it: the tier describes the key custody and pipeline behind a
registry, not what a release must prove. A per-train channel such as
`stable-2026.3` has the kind of the prefix before its first `-` and selects
that kind's destination.

The release class, derived from the version, restricts which destinations a
plan contains. An edge version (`-dev.YYYYMMDD.N`) plans only edge
destinations. A release candidate (`-rc.N`) plans only candidate destinations.
A final version (`YYYY.M.P`) plans both candidate and stable destinations,
because the same bundle is published to `candidate` and then to `stable`.
Qualification snapshots plan no destinations.

Staging surfaces are maintainer-facing. A staging destination's `build` profile
requires only the build gate, and its channel moves as soon as the publication
is read back. Production destinations are consumer-facing and require that a
staging destination of the same release is already published.

### Profiles

A profile is a closed obligation bundle. The shipped values are in
[`qualification/modules/profiles.nix`](../../qualification/modules/profiles.nix):

| Profile | Requirements | Claims | Change scoped | Soak | Reviews | Complete matrix | Transaction review | Fitness (max age) | Rings (cumulative partitions @ observation) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `build` | `build-integrity` | none | no | none | 0 | no | no | none | 256 @ 0 |
| `smoke` | `build-integrity`, `staging-delivery`, `package-function` | functional (A2) | yes | none | 0 | no | no | none | 256 @ 0 |
| `functional` | `smoke` plus `rollout-health` | functional (A2) | no | none | 1 | no | yes | `storage-restore` 14 d, `alert-delivery` 14 d, `authority-recovery` 90 d, `hub-restore` 90 d | 256 @ 0 |
| `soak` | `functional` plus `rollout-observation` | qualified (A2 and A3) | no | 7 days | 1 | yes | yes | `functional` plus `key-rotation` 90 d | 4 @ 24 h, 32 @ 24 h, 128 @ 48 h, 256 @ 0 |

The fields mean:

- **Requirements** are release- and package-scoped requirement IDs, each
  required at its own phase. Image and container requirements enter through
  the selected claims.
- **Claims** selects target claims. `functional` selects every `*-functional`
  claim (A2, staging phase). `qualified` adds every `*-qualified` claim (A3,
  complete phase).
- **Change scoped** narrows image, container, and package obligations to what
  changed relative to the predecessor. See [change scoping](#change-scoping).
- **Soak** is the minimum observed window for A3 claims and
  `rollout-observation`.
- **Reviews** is the number of distinct release-evidence reviewer signatures
  required over each report the destination admits.
- **Complete matrix** rejects a plan with any blocked package/platform cell.
- **Transaction review** stops the pipeline after `prepare-registry` until an
  operator accepts the isolated registry transaction.
- **Fitness** names the attestation kinds that must be fresh and
  binding-matched when the destination is published or advanced.
- **Rings** are ordered cumulative partition counts. Each ring must be observed
  for its stated time before the next ring advances. The last ring is always
  256. A single `256 @ 0` ring advances every partition at once.

`soak` is the only profile whose soak and rings are overridable. The other
profiles mark nothing overridable.

Every profile is subject to floors enforced by both the Nix module and the Rust
contract type:

- every profile requires `build-integrity`;
- `qualified` claims require `rollout-observation` and a soak of at least one
  day;
- rings are strictly increasing and end at 256;
- fitness kinds must be declared in the contract; and
- a candidate or stable destination whose profile selects claims requires at
  least one reviewer, on every tier. Edge makes no support promise, so its
  automated A2 evidence is published without a review.

A reviewed contract revision may change shipped values with `mkForce`, within
those floors. Record the frozen plan's values; the plan binds each
destination's profile by digest.

### Hold points by destination

Each requirement has one phase. The phases a destination actually exercises
follow from its profile:

| Destination | Build | Staging (before publication) | Rollout (before each ring) | Complete |
| --- | --- | --- | --- | --- |
| `staging/*` | `build-integrity` | none | none | none |
| `production/edge` | `build-integrity` | `staging-delivery`, changed `package-function` cells, functional claims of affected targets | none | none |
| `production/candidate` | `build-integrity` | `staging-delivery`, every `package-function` cell, every functional claim | `rollout-health` | none |
| `production/stable` | `build-integrity` | as `production/candidate` | `rollout-health`, fresh for every ring | `rollout-observation`, every qualified claim |

The staging phase always tests the public bytes on the staging surface. Rollout
and complete phases test the destination's own surface. Only a profile that
selects `qualified` claims (`soak`) has a complete phase: its destination
needs a complete-phase report and the release-evidence completion approvals. A
destination of any other profile records `complete` automatically when its
final ring's channel advance and public read-back succeed.

### Change scoping

A change-scoped profile (`smoke`) applies obligations only where the release
differs from its predecessor:

- image claims apply only when the release is image-affecting;
- container claims apply only when any OCI artifact digest differs; and
- `package-function` applies only to package/platform cells whose artifact set
  differs.

Planning records the decision in an `aos.release.change-scope/v1` document
inside the plan. It compares image artifact digests, OCI artifact digests, and
per-cell package artifact digests with the predecessor manifest.
`step qualify-run` and publication recompute the scope from the finalized
manifest and reject any disagreement. When the predecessor manifest is
unavailable or the predecessor is a qualification snapshot, everything is
affecting. Uncertainty never narrows a campaign.

```json
{
  "schema_version": "aos.release.change-scope/v1",
  "predecessor_manifest_digest": "sha256:<predecessor-manifest-hash>",
  "image_affecting": false,
  "container_affecting": true,
  "changed_package_cells": [["nginx", "aarch64-linux"], ["nginx", "x86_64-linux"]],
  "reason": "image artifact digests unchanged; OCI index and nginx cells differ"
}
```

Non-scoped profiles ignore the change scope and exercise every target and
every published cell.

### Fitness attestations

A fitness attestation proves that the release environment can recover. It
replaces the per-release operator recovery exercises of earlier contracts:
nothing about a single release is observed by restoring a backup, and a quarterly
exercise bound to the identities it covered says more than a rushed one before
every publication.

| Kind | Method | Cadence | Bindings | Checks |
| --- | --- | --- | --- | --- |
| `storage-restore` | automated | weekly timer | `tooling` | `independent-encrypted-backup`, `restore-to-clean-environment`, `offline-verification-of-restored-bundle` |
| `alert-delivery` | automated | weekly timer | `alert-config` | `failed-unit-alert-delivered`, `acknowledged-by-on-call`, `no-secret-material-in-alert` |
| `authority-recovery` | operator | quarterly | `signer-roster` | `key-custody`, `recover-encrypted-authority-backup`, `test-signature-per-role-verifies` |
| `hub-restore` | operator | quarterly | `surface`, `hub-schema` | `isolated-hub-restore`, `portable-database-export-import`, `anonymous-readback-of-restored-deployment` |
| `key-rotation` | operator | quarterly | `signer-roster`, `surface` | `registry-key-rotation-trust-continuity`, `unauthorized-replacement-rejected`, `interrupted-publication-single-final-state` |

The maintainer machine's `aos-release-restore-check` and
`aos-release-alert-check` services record the automated kinds. Operators record
the others with `aos maintain release fitness run <kind> --report PATH`, or with the
report on standard input, after performing the exercise in the
[release checklist](release-checklist.md#fitness-exercises). The input is an
`aos.release.fitness-report/v1` exercise report: `performed_at`, `operator`,
and a `checks` map giving each of the kind's checks as `{passed, detail}`. The
command copies those fields into the attestation below, adds the live
bindings, and records the report's SHA-256 as `evidence_digest`.
Profiles accept automated attestations for at most 14 days and operator
attestations for at most 90 days.

A binding names an identity the attestation carries and publication compares
with the live value:

| Binding | Live value |
| --- | --- |
| `surface` | The destination surface identity: the Hub deployment ID, or the static surface identity served at `.aos-surface` |
| `hub-schema` | The Hub schema version reported by the deployment. A static surface has none; the binding is recorded as `null` and is satisfied vacuously |
| `signer-roster` | Digest of the plan's `signers` list, canonical JSON under the domain `aos.release.signer-roster/v1` |
| `tooling` | Digest of the installed release tooling closure's store path |
| `alert-config` | Digest of the maintainer configuration's `[alert]` section |

A binding mismatch makes an attestation unusable regardless of its age. A new
signer roster therefore requires fresh `authority-recovery` and `key-rotation`
attestations; a new production surface requires fresh `hub-restore` and
`key-rotation` attestations for that surface; a new `aos` tooling closure
requires the next restore check to run before a `functional` or `soak`
destination can be published.

An attestation is canonical JSON signed with the standard receipt envelope by a
release-evidence key, stored under the maintainer configuration's
`fitness_root` as `<kind>/<performed_at>.json`:

```json
{
  "schema_version": "aos.release.fitness-attestation/v1",
  "kind": "hub-restore",
  "registry": "andyl/main",
  "performed_at": "2026-09-14T15:00:00Z",
  "checks": {
    "isolated-hub-restore": {"passed": true, "detail": "Restored recovery point rp-0914 into hub-restore-test."},
    "portable-database-export-import": {"passed": true, "detail": "Exported and imported the portable database; row counts reconcile."},
    "anonymous-readback-of-restored-deployment": {"passed": true, "detail": "Read back every indexed object anonymously."}
  },
  "bindings": {"hub-schema": "2026-09", "surface": "production-2026-09"},
  "evidence_digest": "sha256:<restricted-report-hash>",
  "operator": "dplecki",
  "authority_id": "release-evidence-v1"
}
```

`checks` contains exactly the kind's checks, all passed. `evidence_digest`
binds the retained restricted report; the attestation itself carries no
secret, provider account, or internal address. Attestations are
maintainer-wide, not per release: one fresh attestation serves every release
that publishes while it remains valid.

### Profile overrides

A profile override is the only way to relax a destination's obligations. It is
how AOS handles an emergency; no release class relaxes obligations. An
override is an `aos.release.profile-override/v1` document, threshold-signed by
release-evidence keys (one envelope per signer, reaching the role threshold),
that names one release, one destination, and an incident record:

```json
{
  "schema_version": "aos.release.profile-override/v1",
  "registry": "andyl/main",
  "release_id": "release-2026.9.1",
  "destination": "production/stable",
  "incident_reference": "INC-2026-0914",
  "soak_seconds": 86400,
  "rings": [{"partitions": 32, "observe_seconds": 43200}, {"partitions": 256, "observe_seconds": 0}],
  "authority_id": "release-evidence-v1",
  "approved_at": "2026-09-14T16:00:00Z"
}
```

An override may set only fields the profile marks overridable. For the shipped
contract that is `soak_seconds` and `rings` of `soak`, so only
`production/stable` can be overridden. Two floors still apply: soak may not go
below one day, and rings must still end at 256.

An override never relaxes gates, selected claims, change scoping, reviews,
matrix completeness, transaction review, fitness, signature thresholds,
contributor authorization, closure and corresponding-source integrity, public
read-back, or the staging-before-production order.

The plan references each accepted override by digest, so an override changes
the plan digest: an emergency is planned as such, before any build. A plan that
references an override may also select a reviewed `dplecki/hotfix-*` source
branch; see [generate the plan](canonical-releases.md#generate-the-plan). An
override offered after the release is built is rejected; start a new release
instead.

## Target support matrix

The support matrix records compatibility claims and the evidence supporting them.
Each claim identifies an artifact, a function, an environment scope, and an
assurance level. Release policy specifies the minimum assurance required for
selected claims. The destination's profile selects which claims apply and sets
their observation window and review obligations.

### Assurance levels

| Level | Evidence required | Permitted claim |
| --- | --- | --- |
| A0: unassessed | No accepted compatibility assessment or applicable execution evidence | Compatibility is unknown |
| A1: assessed | Reviewed CPU/ABI requirements, firmware and device interfaces, enabled kernel drivers, required firmware, and known exclusions | Expected to work within the documented compatibility scope; no direct execution claim |
| A2: exercised | A1 assessment plus direct tests of the exact artifact and stated functions on recorded configurations, with expected and observed results | The listed functions passed on the tested configurations |
| A3: qualified | A2 evidence plus all applicable acceptance checks, update/recovery transitions, the profile's soak window and required review | The complete stated contract passed qualification on the tested configurations |

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
| OCI container | aarch64 | containerd/runc inside a QEMU TCG `virt` guest on x86_64 Linux | A3, emulated functional contract | `container-aarch64-linux`: persistent network workload; record the physical host, guest and container layers |
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
at completion. A profile with `claims = "functional"` selects only the A2
claims; `claims = "qualified"` selects both. A3 requires the complete
functional and recovery checks and the profile's soak window on that same
recorded configuration. Staging evidence does not award A3 before observation
completes, and a destination whose profile selects no A3 claim never awards it.

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
A profile with `require_complete_matrix` (`soak`) rejects a plan with any
blocked package/platform cell.

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
| Observation | Run mixed network, package and persistent-data operations for the profile's soak window; retain attempts, successes, failures, reboot/recovery counts and monitoring records; no unexplained crash, integrity mismatch, data loss or unresolved required-function failure |

The cycle minima are numeric requirement bounds, composed by the image and
container modules and bound into each case.
They are engineering acceptance thresholds, not reliability probabilities.
Scenario reports must show the counts and comparisons, not just a success flag.

### OCI-container acceptance

Run these checks with AOS-built containerd/runc on native x86_64 Linux and
inside a full-system QEMU TCG ARM64 Linux guest on x86_64 Linux.
Use AOS-built QEMU and guest runtime tools;
host binfmt user-mode emulation is outside this reference scope.

Record the physical x86_64 host, QEMU `virt` guest and ARM64 container as three
ordered layers for the ARM64 target, including the host and guest kernels,
QEMU version/machine/CPU model, runtime versions and CPU identities. This
qualifies the recorded emulated workload; it makes no native ARM64 hardware
or performance claim. The same topology must cover staging and observation.
Native ARM64 coverage requires its own explicit target and evidence.

Existing fleet tests provide regression coverage; the same checks against the
exact published artifacts are required before a public release can pass this gate.

| Test | Pass condition |
| --- | --- |
| Pull and platform selection | A clean client anonymously pulls by the release's immutable digest; the signed index selects the correct architecture; selected manifest/config/layer digests match the release; execution matches the declared native or full-system TCG topology |
| Documented launch | The published run command starts the declared workload with only its documented user, mounts, capabilities and privileges; readiness and HTTP/TLS checks pass; no undeclared privileged mode or host access is added to make the test pass |
| Network | Published ports and container DNS work; restart/recreation does not leave stale connectivity; traffic reaches the intended container |
| Lifecycle and state | Complete 10 stop/start/recreate cycles using a named volume; each graceful stop respects the documented timeout and exit behavior; numbered committed records and hashes survive removal/recreation; an abrupt kill preserves records already acknowledged as durable |
| Limits and signals | Runtime CPU/memory limits are applied and observed; the workload handles its documented termination signal; memory exhaustion has the documented failure/restart behavior without corrupting committed volume data |
| Image replacement | Recreate with the candidate digest using the existing volume, then exercise the documented recovery/rollback path; verify data compatibility rather than assuming image rollback reverses data migrations |
| Profile and observation | Verify the experimental/production registry and trust identities, run the persistent network workload for the profile's soak window, and retain operation counts and failures with no unresolved required-function or integrity failure |

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
checks, storage errors and thermal behavior during the profile's soak window; unexplained
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

Package probes are immutable declarative programs built with
`mkQualificationPackageProbe`. Each probe names the package and contains a
primary operation plus a bad-input operation. An operation records its input,
the command or public API being exercised, the expected result, regular input
files, ordered command steps, and exact output-file assertions. Primary steps
must expect success. The bad-input operation must observe a nonzero status or
mark an exact stdout/stderr assertion as the rejection result.

Commands use explicit paths. `@profile-out@` and
`@profile-output:<name>@` address the APM-installed output, while `@out@` and
`@output:<name>@` address the corresponding imported output. `@cc@`, `@cxx@`,
`@python@`, and `@bash@` are the only harness commands. The runner rejects an
executable outside the signed package closure, installed profile roots, and
those named harness tools. It also requires exact stdout or stderr assertions
where a successful command claims to have observed rejection. This keeps a
probe from silently consulting a host tool or reporting an unobserved error
path.

## Inspect and freeze the contract

```sh
aos maintain release step contract --registry andyl/experimental
aos maintain release step contract --registry andyl/main --to production/stable
aos --json release step contract --registry andyl/main --to production/candidate \
  --output qualification-contract.json
aos maintain release step contract --registry andyl/main --input qualification-contract.json
```

Without `--to`, the command prints the destination table for the registry tier
with each destination's profile. With `--to`, it prints that destination's
profile, profile digest, and gate identities. The gates shown assume every
target is affected; a change-scoped plan may require fewer. The output lists
requirements and never claims that they passed. `--output` writes a new
canonical contract file and refuses replacement. `--input` supports inspection
without Nix or network.

`aos maintain release new` exports the contract itself and freezes it into the plan.
Plans use `aos.release.plan/v1` and embed the complete
`aos.release.qualification-contract/v1` (`aos-system`). A plan or contract
with any other schema or identity is rejected.

Record a `qualification_predecessor` with the same registry, a distinct
`release_id`, and the verified preceding `manifest_digest`. The maintainer
configuration's `predecessor_bundle` supplies it to `aos maintain release new`. First
public releases use the restricted, non-public
[qualification snapshot workflow](canonical-releases.md#create-a-first-qualification-predecessor)
as their predecessor. A descriptor alone is insufficient: retain the signed
bundle and verification keys for the image update executor and for change
scoping. A experimental-to-main transition is a new main release and installation
unless a separate authenticated migration contract has been implemented and
qualified.

Every destination requires authentic artifacts, complete closures, source and
license evidence, and a reproduced build through `build-integrity`. Durations
are engineering policy, not statistical failure-rate claims. Record machines,
workload, attempts, successes, failures, and recovery operations for every
observation window.

## Requirements, subjects, and evidence

The qualification catalog uses the AOS `lib.evalModules` fixed point. Feature
modules under `qualification/modules/` own their options, configuration and
assertions. The module registry discovers feature files automatically and
excludes `_`-prefixed implementation files. `qualification/default.nix` accepts
additional `modules`; normal `mkDefault`, `mkForce`, `mkIf`, `mkMerge` and list
ordering rules apply. Required acceptance floors still constrain the result.
Package classifications and target claims derive from the final configuration.
`profiles.nix`, `destinations.nix`, and `fitness.nix` own the three tables
above.

Each requirement specifies its hold point, subject population, observation
method, acceptance checks, numeric bounds, regression coverage, and invalidation
conditions:

| Requirement | Phase | Scope | Selected by |
| --- | --- | --- | --- |
| `build-integrity` | build | release | every profile |
| `staging-delivery` | staging | release | `smoke`, `functional`, `soak` |
| `package-function` | staging | packages | `smoke`, `functional`, `soak` |
| `rollout-health` | rollout | release | `functional`, `soak` |
| `rollout-observation` | complete | release | `soak` |
| `image-installation`, `image-lifecycle`, `image-update-recovery` | staging | image targets | functional claims |
| `container-lifecycle` | staging | container targets | functional claims |
| `image-observation`, `container-observation` | complete | image and container targets | qualified claims |

The coordinator expands the requirements a destination selects into exact
cases:

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

Two ages are fixed in `aos_release::qualification::limits`: rollout
observations and approvals expire after 10 minutes, and any other observation a
report relies on expires after 30 days. A3 cases additionally require
observation at least as long as the destination's soak, or the soak of an
accepted override.

Cases use `aos.release.qualification-case/v1`. Every target observation
includes a reviewed assessment bound to the canonical environment-profile digest. A1 contains the
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

`aos.release.qualification-report/v1` records coordinator-derived claim outcomes
alongside the observations. Consumers recompute those outcomes; an executor
cannot assign its own assurance. Missing, failed and stale optional claims remain
visible and do not block admission. Malformed or incorrectly bound evidence is
rejected even for an optional claim. A complete functional run with insufficient
observation duration can establish A2 but cannot satisfy an A3 obligation. Reports
require the configured authority signatures and the destination's review
threshold before they authorize release operations.

Build observations belong in the immutable manifest. Staging observations
refer to that finished manifest and its staging publication receipt. Rollout
and completion observations are later records; never mutate the original
manifest to add evidence that did not exist when it was signed.

### Scoped gate digests

Each gate identity is digested over only what it depends on, under the domain
`aos.release.gate-policy/v1`:

- a requirement gate digests the requirement; and
- a claim gate `claim-<id>` digests the claim, its target, and the requirements
  the claim references, in contract order.

Each planned destination additionally carries a `profile_digest` over its
profile under `aos.release.qualification-profile/v1`. Soak, review, fitness,
and ring changes therefore change the destination's binding without
invalidating case evidence for unrelated targets. Each gate records whether it
is `blocking`: requirement gates always block, and a claim gate blocks when its
claim does.

A plan's destinations each carry their own gate list, equal to
`contract.gates(destination, change_scope)`. There is no plan-wide gate union.

## Release journal and admissions

Each release keeps an append-only, hash-chained journal
(`aos.release.journal-entry/v1`). It records three global states and then one
state per planned destination:

```text
planned -> built -> finalized -+-> published(staging/c)    -> rolling -> complete
                               +-> published(production/c) -> rolling -> complete
any non-terminal state -> failed
```

- `planned`, `built`, and `finalized` are global and linear.
- A destination may become `published` once the release is `finalized` and
  every surface role in its `after` list already holds a published, rolling, or
  complete entry for the same release. Production destinations wait for
  staging; staging destinations wait for nothing.
- A published destination advances to `rolling` with its first ring, stays
  `rolling` across later rings, and becomes `complete` when its rollout is
  closed.
- Destinations interleave: publishing `production/candidate` does not wait for
  `staging/stable` to complete, and `production/stable` may be published while
  `production/candidate` is still rolling.
- `failed` is reachable from any non-terminal state and is terminal for the
  release bytes. The release succeeds when every planned destination is
  `complete`.

There is no separate qualified state. The signed staging-phase qualification of
a production destination is attached, by digest, to that destination's
published entry. Rollout and completion qualifications are attached to the
rolling and complete entries they authorize. The admissions of one release are
therefore independent per destination: a failure to qualify
`production/stable` does not undo `production/candidate`.

## Collect, review, and sign

`aos maintain release advance` performs this section's steps for each destination and
stops at every human decision. The underlying leaf commands are documented here
because their inputs and outputs are the evidence.

Inspect the actual case population before allocating machines:

```sh
aos maintain release step qualification cases \
  --plan "$WORK/plan.json" \
  --manifest "$WORK/finalized/bundle/release-manifest.json" \
  --to production/candidate --phase staging
```

This command displays requirements, a `case_digests` map keyed by case ID, and
an `environment_profile_digests` map for target cases. It applies the
destination's profile and the plan's change scope. It does not verify
signatures or claim a pass. Use `aos maintain release step verify` with independent
public anchors for verification. `aos maintain release explain --to <destination>`
prints the same population with the current status of every case.

Run `aos maintain release step qualify-run --to <destination> --phase staging
--prepare-only` with the bundle, the staging publication receipt, applicable
executor mappings, and `--qualified-at now` described in
[the runbook](canonical-releases.md#run-the-native-qualification-matrix).
For staging image update cases, also supply the retained snapshot through an
absolute `--predecessor-bundle` path.
Inspect the prepared report and its retained `reports/` directory. Each
reviewer signs an independent review payload with a planned `release-evidence`
key, either through `aos maintain release review` or directly:

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
store. The destination's profile sets the review threshold: `functional` and
`soak` require one reviewer, `smoke` and `build` none. A reviewer may be added
voluntarily where none is required. Human independence and custody are
confirmed in the maintainer checklist; separate key IDs alone do not prove it.
A rejected review (`"accepted": false`) stops the destination; the report must
be recollected.

Repeat `qualify-run` with `--report-input PREPARED/qualification-report.json`
and each `--review-receipt PATH`, omitting `--prepare-only`. The authority checks
and signs the same report. Its output atomically retains report bodies,
reviews, and signatures. Keep that entire directory and the separately retained
`.aos-qualification-attempt-*` directories. `step publish` and `step record`
recheck the original report directory, including its bodies and reviews; a
copied aggregate JSON file alone is insufficient.

For rollout, use `--phase rollout --ring N --prior-generation G` with the
destination's current publication receipt (`--publication-receipt`) and the
current journal. The command derives the ring's partition range from the
planned rings; `G` is the channel generation observed on the live surface.
Rings are numbered from 1 in profile order.

For completion, use `--phase complete` with the destination's publication
receipt and rolling journal. These authority signatures bind the exact report,
policy, manifest, publication receipt, entire journal, and next ring where
applicable. Channel commands require the signed rollout qualification when the
profile has a rollout-phase gate; observations and approvals at rollout must be
at most ten minutes old. Recollect health for each new ring. A completion
approval must also be fresh, while its workload report covers the full soak
window. Campaigns lasting days run outside a single bounded executor process;
import their retained observations for review and admission.

## Native executors

`lib.testing.mkQualificationExecutor` (from `lib/testing`) packages a runner
with explicit `platform`, `identity`, `scenarios`, absolute `workRoot`, and
`timeoutSeconds`. `scenarios` maps case policy IDs, including `claim-<claim-id>`, to absolute executables in
AOS-built Nix closures. Missing implementations fail; an empty adapter is never
a passing gate. Environment-specific adapters and remote macOS transport must
be provisioned before a campaign. All source regression groups are exposed at
`checks.qualification.<requirement-id>` and `checks.qualification.all`.

The RFC-0022 native ability gates are `ability-native-activation`,
`ability-native-kubernetes`, `ability-native-recovery`, and
`ability-native-adapter-matrix`. They use release scope so each staging case
binds the complete finalized non-control artifact set, including the exact
package, native transaction, handler, and image records carried by the release.
A change to the case subjects, qualification policy, executor, or environment
invalidates its observation.

Native package qualification uses the signed `aos.package.qualification`
companion. Its closed probe declarations name exact package/output selectors;
the frozen artifact bindings select immutable payload roots. Release admission
validates the companion's exact bytes and retained store identity, rather than
reconstructing an interface or provider catalog. A package probe proves only
its declared package-function claim. It does not establish a whole-system
activation or recovery claim.

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
scenario against admitted candidate inputs. These are executor-authorized
scenario inputs; they are distinct from the candidate's signed boot baseline.
Ambient store paths or a fixture's self-reported inventory do not supply that
authority.

A selected operation retains its checked desired graph and exact graph digest. Each dispatched attempt is
identified by transaction, effect, semantic revision, action, and durable
journal sequence. Invocation and recovery observations must match that exact
attempt. An observation for another revision, backend, action, or sequence
cannot satisfy its cell.

Live flights retain checked native journal inspection alongside independent
substrate and backend receipt ownership inventories and foreign-state
snapshots. Pending intent, completed outcomes, and committed output mappings
are distinct evidence. Interruption and recovery cases must show dependent
nonexecution after failure, safe handling of incomplete tails, and the exact
ownership and foreign-state results required by the cell. Removal decisions
come from the transaction's explicit `retire` list and target retained or
already durably retired effects; omission from a desired graph does not
authorize retirement.

Native rejection evidence must identify the selected graph and the rejected
attempt, and independently establish that no prohibited dispatch or external
mutation occurred. Schema checks, mocked callbacks, and a successful source
regression cannot substitute for live domain observations. The source-built
`aos.qualification.native-runtime-audit` checks generic runtime boundaries
separately; passing it does not qualify Kubernetes, storage, services, boot, or
any other domain.

Source-candidate regression derivations and release staging cases remain
separate. Release admission requires fresh executor observations for the exact
frozen subjects and acceptance checks. Whole-system native fleet qualification
is incomplete until every applicable domain operation and recovery case has
produced its required evidence. An unfinished scenario must leave the gate
unsatisfied. An x86 fleet does not establish direct aarch64 execution.

Kubernetes qualification requires actual native package modules, authenticated
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
and admission roots before booting that QCOW2 with
KVM, UEFI Secure Boot, and a software TPM. It then confirms through the guest's
recorded running generation, booted UKI digest, kernel, root hash, and host
native admission and retained transaction identities that execution stayed on
those published subjects. A checked desired graph alone does not prove that its
effects ran.

The production-only image-rollout scenario additionally requires the frozen
predecessor manifest and its downloaded object bundle. It rejects a missing or
mismatched bundle before boot, validates the predecessor's complete finalized
server image controls, and starts independent healthy and failed-health flights
from exact copies of that predecessor QCOW2. The candidate is obtained only by
retaining the image's baked authenticated registry trust anchor, redirecting it
to the bounded HTTPS staging Hub origin, and replacing its channel with the
exact finalized release-version tag. The healthy flight independently observes
the health hook and native journal before allowing physical boot commit, then
proves expiry retires both rollout roots and retained UKIs. The failed-health
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

Native boot evidence binds the image-owned host and initrd transaction,
packages, evaluation snapshot, and admission roots to the published assembly.
Read-only inspection of the native effects journal distinguishes desired
configuration, pending durable dispatch intent, and committed output mappings.
It does not repair incomplete tails or treat graph digests as live-state proof.
Live operation evidence records the exact transaction, effect, revision, action,
and journal sequence alongside independently observed backend ownership and
foreign-state snapshots. A source-built native runtime audit is separate from
domain qualification; its success does not qualify a fleet scenario that has
not completed its own native operation and recovery checks.

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
that outer host separately from the ARM64 guest. x86_64 disk qualification still
requires an x86_64 host with KVM.

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
all lifecycle checks and does not issue a qualification response. The host
collector must attach its observed physical and QEMU inventory, then bind and
validate the combined report through `qualification respond`. A guest-local two-layer report cannot satisfy this profile;
report import does not synthesize the missing outer host or QEMU evidence.
Missing reports fail closed. Automated guest provisioning and collection of
this combined inventory remain operator setup work before release readiness.
The topology change alters the contract digest: regenerate requests, plans,
assessments and case-bound reports; do not reuse earlier native-only evidence.

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
manifest, receipt, or case is rejected.

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
registry, release, publication receipt, manifest, and case identities first. It
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
executor cases; they are [fitness attestations](#fitness-attestations). Each
report-backed adapter
drains the coordinator request, captures the selected report without following
links, and binds it through `qualification respond`. A missing, changing,
stale, malformed, incorrectly identified, or case-incomplete report fails the
attempt.

A fixture gate proves regression behavior only. The native Hub fleet uses
visibly synthetic observations and timing to test admission mechanics; those
records cannot establish release workload duration or physical reliability.
The same acceptance conditions govern real automated and operator adapters.

## Static surfaces

Qualification does not require an AOS Hub. A surface may be a static origin
(filesystem, S3, or SFTP, read back over HTTPS or `file://`), and every
requirement above applies unchanged. The differences are confined to identity
and receipts:

- executors download the staging-phase subjects from the staging surface's
  read-back origin, exactly as they would from a Hub route;
- the surface identity is the string served at `<readback>/.aos-surface`
  rather than a Hub deployment ID, and `staging-delivery` and `rollout-health`
  check it before and after publication;
- publication and channel receipts on a static surface are
  `aos.release.publication-receipt/v1` documents signed by the plan's
  `surface-receipt` role instead of a Hub receipt key; and
- the `hub-schema` fitness binding is recorded as `null`.

The `hub-restore` fitness kind still applies to a static production surface:
restore the origin's object set and channel generation records into an
isolated origin and read it back anonymously. The supported surface pairs and
upload mechanics are in
[static surfaces](canonical-releases.md#static-surfaces).

## Qualification roles and public status

Package roles describe consequences: `system-integrity`, `qualified-workload`,
or `general-catalog`. Dependencies inherit the obligations of the root that
uses them. The authenticated runtime closure is the source of dependency
membership. A library used by boot or recovery cannot avoid those tests by
being listed as a general catalog package. `qualification cases` reports the
strongest effective role inherited through the signed package-NAR relationship
graph for each package cell.

Public status is separate: qualified for the experimental registry, preview, blocked, or not
applicable. A reference target in the contract is a requirement, not a passing
hardware claim. Publication integrity applies equally to preview packages.
Known failure of an advertised basic function blocks that artifact. Successful
builds and `--version` checks do not establish complete functionality.

## Test execution and reuse

Package qualification expands every published package/platform cell into a
separate case. A package published for both `x86_64-linux` and `aarch64-linux`
requires successful observations for both; a local check on one architecture
does not satisfy the other. Package publication support policy determines
which cells apply. The package probe schema has no architecture selector that
can silently exempt an otherwise published cell. Only a change-scoped profile
narrows the population, and only to cells whose artifact set changed; see
[change scoping](#change-scoping).

Recovery and K3s package cases also bind their published execution image. The
shared policy's `qualification.packageExecutionImageVariant` defaults to
`aos-experimental`, whose canonical image contains the public release profile and
trust inputs. Recovery and fleet executors derive their image variant from the
same package rule. Alternate reviewed contracts can select another canonical
published variant; a fixture image name is not an implicit substitute. Plan
validation rejects a missing execution image or platform before builds and
signing, rather than waiting for staging case expansion.

`qualify-run` routes each case to its platform's `--executor` mapping. The
package executor runs natively and validates the requested platform; it does
not create a VM itself. To qualify packages in Linux VMs, provision an executor
inside each architecture's VM and route the corresponding mapping to it.
Installing both executor closures on a coordinator does not establish that
either ran inside a VM. Retain the execution environment with the resulting
evidence. Image qualification separately boots the exact published image.

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
invalidate dependent results. Live surface health always needs a fresh
observation. Uncertain impact selects the broader campaign. Scoped gate digests
keep this rule honest: a claim gate changes only when its claim, target, or
referenced requirements change, so evidence for an unrelated target survives a
policy edit elsewhere in the contract.

## Release-train support

Support is a forward-looking promise, separate from the evidence that a release
passed its gates, and it is reviewed with the rest of the contract.
[`qualification/modules/support.nix`](../../qualification/modules/support.nix)
declares it:

```nix
qualification.support = {
  default = { kind = "standard"; superseded_after_trains = 2; };
  trains."2026.9" = { kind = "lts"; supported_until = "2028-09-30"; };
};
```

A stable release `major.minor.patch` belongs to the train `major.minor`. A train
without an entry follows `default`: it stays supported until
`superseded_after_trains` newer stable trains exist. An explicit entry may give
a `supported_until` date, which then decides on its own; an `lts` train must
state one. The module rejects train keys with leading zeros, impossible dates,
LTS trains without an end date, and a rolling count of zero, and the exported
contract carries the policy under `support`. Current contracts must state it;
the Rust contract type validates the same rules.

Each source line states only what it owns. The `train/YYYY.M` branch that
maintains a train declares `trains."YYYY.M"` for that train alone; `master`
declares `default`. Registry finalization copies the release's own train entry
into the signed registry's `[support]` table and refuses a contract that names
another train, so a backport on an old train can extend that train's support
without touching newer ones, and no branch can rewrite the roadmap of another.
A Hub surface indexes the table with the registry metadata and renders it on
the Releases page; a static surface serves it only inside the signed registry.
Changing the promise is therefore a reviewed contract change on the owning
branch followed by that branch's next release, never a surface setting.

## Public release record

Registry finalization precedes qualification, so the qualification outcome
cannot live in the registry tree. After the staging-phase report for a
production destination is signed, `aos maintain release step record` composes
`aos.release-record/v1` from the frozen plan, the final manifest, the signed
qualification, and the public report, and the TUF and compose-surface steps
authorize and serve it beside the release manifest on that destination's
surface. The
record carries the result, policy, authority, and admission time; each claim's
required and achieved assurance and disposition; the train's support
statement; provenance digests; and the exact signed envelope. Achieved
assurance describes the evidence at admission; later invalidation is recorded
in a subsequent release, not by editing the record. See
[`canonical-releases.md`](canonical-releases.md#compose-the-public-release-record).

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
