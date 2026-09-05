# AOS release contract

AOS uses the same functional contract for testing and production. Each release
records its exact policy, artifacts, target configurations, and qualification
evidence. A target listed in the policy is required work; it is qualified only
after its release evidence passes. The existence of this document does not
declare the current source or any live deployment qualified.

## What the server contract covers

On the named reference configurations, the contract requires authenticated
installation, persistent headless-server provisioning, administrative access,
SSH/DNS/time/network configuration, machine-wide package lifecycle, host
configuration activation/rollback, image updates, boot fallback, offline
recovery, and bounded maintenance of retained generations.

Reference disk targets are x86_64 QEMU/KVM with q35 and AArch64 QEMU virt with
AOS-built UEFI firmware. Both require virtio storage/network, persistent
firmware variables and TPM 2.0 state. Qualification starts at 2 vCPUs, 8 GiB
RAM, and a 32 GiB disk. These are reference configurations, not measured
minimum requirements. Arm emulation supports functional claims, not native
performance or hardware claims.

The disk contract includes externally finalized Secure Boot, measured boot,
dm-verity, encrypted state, and authenticated recovery with the release's own
authorities. SELinux is explicitly outside this contract until a labeled root
and enforcing policy pass their own qualification.

OCI artifacts are qualified separately on pinned containerd/runc environments
for both Linux architectures. Containers share their host kernel; disk boot,
TPM, encrypted-state, and firmware claims do not transfer to an OCI image.

The initial reference workloads are nginx HTTP/TLS and a networked container
with persistent state. Other application capabilities require their own
workload evidence. Availability of raw, QCOW2, VMDK, or VHD encodings is not a
qualification claim for every compatible hypervisor, cloud, or physical server.

## Interpret package and hardware status

| Status | Meaning |
| --- | --- |
| Qualified for testing | The declared workflow passed on the named release/platform/configuration; production support is not promised |
| Preview | Baseline artifact and functional checks passed, with explicitly narrower workload evidence |
| Blocked | Required work or evidence is missing or failed |
| Not applicable | A recorded eligibility rule excludes that platform |

All published packages require authenticated complete closures, source/license
records, applicable security review, and meaningful package-specific functional
checks. Qualification of one configuration does not cover every upstream
feature. A package's role in boot, updates, trust, storage, or recovery raises
its required evidence even when it is also offered in the general catalog.

Bare-metal models, native Arm machines, specialist storage, GPUs, IPMI,
watchdogs, Kubernetes deployments, additional hypervisors, and cloud targets
need explicit extensions. macOS receives packages only, with native execution
evidence on the corresponding Intel or Apple Silicon macOS environment.

## Updates, data, and support

Normal releases qualify the preceding accepted snapshot to the candidate,
recovery/rollback, and another successful update within the same trust epoch.
Image rollback does not reverse application data migrations. Preserve backups
and follow each workload's declared migration and recovery procedure.

`andyl/testing` follows edge and remains experimental. Planned incompatibility
or a trust-root reset may require reinstallation, but a release must state that
boundary before publication. Main is a separate trust and lifecycle domain;
testing releases do not become main releases through a channel move.

Production adds complete required matrices, independent review, longer
observation, durable recovery, and explicit compatibility/support obligations.
Neither a finite qualification campaign nor a passing build establishes an
uptime SLA. Stock unprivileged per-user package mutation remains outside the
initial administrative server contract.
