# Qualification support matrix and acceptance checks

This page defines the target support matrix of the
[release qualification](qualification.md) contract: assurance levels, test
axes, required coverage, and the acceptance checks for disk images, OCI
containers, physical hardware, cloud VMs, and packages, followed by package
roles and public status.

## Target support matrix

The support matrix records compatibility claims and the test results supporting
them.
Each claim identifies an artifact, a function, an environment scope, and an
assurance level. Release policy specifies the minimum assurance required for
selected claims. The destination's profile selects which claims apply and sets
their observation window and review obligations.

### Assurance levels

| Level | Results required | Permitted claim |
| --- | --- | --- |
| A0: unassessed | No accepted compatibility assessment or applicable test results | Compatibility is unknown |
| A1: assessed | Reviewed CPU/ABI requirements, firmware and device interfaces, enabled kernel drivers, required firmware, and known exclusions | Expected to work within the documented compatibility scope; no direct execution claim |
| A2: exercised | A1 assessment plus direct tests of the exact artifact and stated functions on recorded configurations, with expected and observed results | The listed functions passed on the tested configurations |
| A3: qualified | A2 results plus all applicable acceptance checks, update/recovery transitions, the profile's soak window and required review | The complete stated contract passed its tests on the tested configurations |

Levels express how much testing backs a claim, not statistical reliability or
certification. Successful artifact builds establish availability, but do not
establish A1 hardware compatibility by themselves. Failed checks, expired
results and known incompatibilities are recorded separately from assurance;
none may be hidden by assigning a lower level. Published artifacts always
require signatures, complete closures and corresponding source, regardless of
hardware assurance. Mark a known failing scope incompatible even if historical
results reached A3.

A2 and A3 apply to the recorded configuration set. A broader compatibility claim
requires its own A1 assessment. For example, a reviewed CPU-family claim may be
A1 while a subset of specific CPU SKUs and platform configurations is A3. The
family retains A1 outside that tested subset. A CPU result alone does not cover
a motherboard, NIC, storage controller or their combined installation.

### Test axes

Use one row for each distinct claim and scope. Multiple rows may cover the same
architecture at different assurance levels.

| Axis | Required scope and result fields |
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
the actual tested configurations and results separately for each release.

| Environment | Architecture | Accelerator/runtime | Minimum assurance | Required configuration |
| --- | --- | --- | --- | --- |
| QEMU | x86_64 | KVM | A3 | `disk-x86_64-linux`: `q35`, persistent UEFI/TPM, virtio disk/NIC; record host and guest CPU identities |
| QEMU | aarch64 | TCG | A3, functional contract | `disk-aarch64-linux`: `virt`, persistent UEFI/TPM, virtio disk/NIC; record emulated CPU model/features |
| OCI container | x86_64 | containerd/runc, native host | A3 | `container-x86_64-linux`: persistent network workload and recorded host configuration |
| OCI container | aarch64 | containerd/runc inside a QEMU TCG `virt` guest on x86_64 Linux | A3, emulated functional contract | `container-aarch64-linux`: persistent network workload; record the physical host, guest and container layers |
| QEMU | x86_64 / aarch64 | Other architecture/accelerator combinations | Set per additional claim | Separate machine/CPU/device configuration and results |
| Physical hardware | x86_64 / aarch64 | Native | Set per claim | CPU SKU set, chipset/SoC, firmware, device/driver combinations |
| Cloud VM | x86_64 / aarch64 | Provider virtualization | Set per claim | Provider/service, exact instance SKU, region and virtual device profile |

[`qualification/modules/qemu.nix`](../../qualification/modules/qemu.nix) and
[`containers.nix`](../../qualification/modules/containers.nix) define the four
mandatory reference configurations. A platform listed in
[`qualification/deferred-platforms.nix`](../../qualification/deferred-platforms.nix)
keeps its configurations, but they are optional and carry no claims until the
platform returns; the release ships no artifact on it. The list is currently
empty, so both Linux platforms carry their claims.
Their required checks cannot be waived by lowering assurance. Additional claims
must state their required level and release-blocking status before the plan is
frozen. Additional A3 image/container claims require corresponding target cases
and scenarios. Physical or cloud categories receive no blanket assurance from
the reference VM results.

Each required target has a release-blocking A2 claim at staging and an A3 claim
at completion. A profile with `claims = "functional"` selects only the A2
claims; `claims = "qualified"` selects both. A3 requires the complete
functional and recovery checks and the profile's soak window on that same
recorded configuration. Staging results do not award A3 before observation
completes, and a destination whose profile selects no A3 claim never awards it.

A2 and A3 outcomes cover the exact inventory identified by their environment
digest. Declare separate required targets for the CPU, board, device and runtime
combinations that must each be exercised. A target's compatibility predicates
define which configurations may satisfy its case.

### Release results matrix

Retain this matrix with the release records and include the approved claims in
release support information. Every row must contain:

| Field | Required value |
| --- | --- |
| Claim | Stable identifier and specific function or contract, such as installation, network operation, or complete image lifecycle |
| Compatibility scope | Explicit architecture, CPU/features, platform and device predicates; runtime/accelerator or provider/SKU where applicable |
| Tested configurations | Inventory IDs for the exact combinations exercised; an empty set for assessment-only claims |
| Required assurance | A1, A2 or A3, plus whether failing this obligation blocks release |
| Achieved assurance and result | Highest currently supported level; pass, fail, missing or stale results; known incompatibilities |
| Results | Artifact/plan/case digests, assessment references, test reports, dates, operation counts, observation window and reviewer |
| Maintenance | Owner, result expiry and changes that invalidate the claim |

The matrix is a reviewed release record. Required executor cases and signed
reports remain what approves a release; matrix entries cannot replace missing
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
profile. Preserve historical results, mark invalidated results stale, and obtain
fresh results before retaining the affected assurance claim. A shared defect
blocks every release obligation whose scope includes it.

### Images, packages and optional hardware features

Image lifecycle, individual devices, optional features and package/platform cells
may carry separate claims. Each advertised disk format requires equivalence
verification; provider import is a separate cloud claim. Every published package
needs the functional checks below, with additional obligations inherited from its
system-integrity or workload role.

Record optional features such as redundant storage, GPU acceleration, watchdogs
and server management with their own functions, configuration scope and results.
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
covers the recorded emulated workload; it makes no native ARM64 hardware
or performance claim. The same topology must cover staging and observation.
Native ARM64 coverage requires its own explicit target and results.

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
require separate feature tests.

An A3 physical-image claim requires the disk-image checks on each selected
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
hardware/driver faults block the affected claim pending diagnosis.
Retest affected coverage after kernel, driver, firmware or boot/security changes.

### Cloud-VM acceptance

Test each cloud claim against its provider, service, exact instance SKU,
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

## Package roles and public status

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
