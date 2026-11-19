# Build and customize release images

This guide is for AOS release maintainers and platform integrators. End users
should download the published AOS image, customize the host with `host.nix`,
and install packages with `apm`.

Runtime `host.nix` activation evaluates and atomically applies networking,
users, access, services, packages, and other general host policy. Keep only
image capabilities, bootstrap reachability, and initial trust roots in the
release image; put machine-specific policy in authenticated `host.nix`.

Changes to signing authorities or image-baked anchors must follow [Maintain
the AOS trust model](trust-model.md). Operators can follow the resulting boot
and package chain in [Use Secure Boot and verify package
trust](../users/aos/secure-boot.md).

## Create a system variant

Files under `systems/` are discovered automatically. A file named
`systems/acme-server.nix` produces an evaluated system at
`systems.acme-server`, disk outputs named `acme-server-image-<format>`, and an
associated default OCI artifact at
`systems.acme-server.build.defaultContainer`.

```nix
# systems/acme-server.nix
{...}: {
  imports = [./server.nix];

  aos.roles.server.enable = true;
  aos.networking.hostName = "web-01";

  # Keep physical root capacity independent from the artifact growth gate.
  # The 1 GiB default can be overridden for a device class when needed.
  aos.image.rootPartitionMiB = 1024;

  # These maxima are release gates. Verity and ESP values also size their
  # partitions; maxRootMiB does not resize the root A/B slots.
  aos.image.budgets = {
    maxRootMiB = 512;
    maxVerityMiB = 16;
    maxInitrdMiB = 128;
    maxBootExecutableMiB = 160;
    maxFirmwarePartitionMiB = 384;
    maxRuntimeClosureMiB = 768;
    maxDownloadMiB = 640;
  };

  aos.networking.interfaces.eth0 = {
    address = "10.0.0.20/24";
    gateway = "10.0.0.1";
    dns = "10.0.0.53";
  };

  aos.services.ssh = {
    enable = true;
    port = 22;
    permitRootLogin = "prohibit-password";
    passwordAuthentication = false;
    kbdInteractiveAuthentication = false;
  };

  environment.etc."ssh/authorized_keys/root" = {
    text = "ssh-ed25519 AAAA_REPLACE_ME ops@example.com\n";
    mode = "0600";
  };

  aos.firewall.allowedTCP = [443];
}
```

Interface names are deployment-specific. The server default uses DHCP on
Ethernet interfaces matching `en*` when no explicit interface is declared.

Keep private keys and service credentials out of the module and Nix store.
Public trust anchors and SSH public keys may be part of a release image.

## Understand the shared artifact evaluation

Disk and OCI artifacts are projections of one system-module evaluation. The
bootable host remains `system.build.toplevel`; replacing it with a container
would erase the kernel, initrd, services, and activation contract. The sibling
`system.build.defaultContainer` is the default container associated with every
disk format of that system, while `system.build.containers.<name>` exposes all
of its container definitions. This system-level association avoids repeating
the same container pointer on raw, QCOW2, VMDK, and VHD encodings of one logical
image.

Option ownership is explicit:

| Namespace | Applies to |
| --- | --- |
| `aos.system`, `environment.systemPackages`, `aos.release` | Shared system identity, userland, and release/registry policy |
| `aos.image` and boot/storage/security options | Bootable disk artifacts only |
| `aos.containers` | OCI filesystem, runtime, publication, and default-container selection only |

The OCI projection consumes the evaluated userland packages and shared release
profile; it does not package or retain `system.build.toplevel`, the kernel,
initrd, bootloader, TPM state, or disk layout. Container-specific assertions
are enforced by the same system evaluation and also when the container output
is forced directly.

`modules/image/container.nix` owns the OCI projection and imports the shared
base-container recipe from `modules/image/_container-definition.nix`. The
underscore-prefixed helper is excluded from automatic module discovery. It
combines the owning system's userland with explicit runtime, shell, and CLI
roots, and defines the OCI layers and runtime defaults.

The public `aos-experimental` system demonstrates the pattern. Its disk and OCI
artifacts contain exactly one `andyl/experimental` registry seed, select `edge`, and
carry the same experimental-use warning and trust anchor. The disk displays the
warning on the console and SSH login; the OCI entrypoint prints it to standard
error before starting the requested command, based on the immutable release
profile rather than an overridable OCI environment value. The production server's
compatibility container remains available as `container-aos-*`; the experimental
outputs use `container-aos-experimental-*`.

## Compose release policy

Put shared policy in an underscore-prefixed file so system discovery does not
publish it as a standalone image:

```nix
# systems/_acme-common.nix
{pkgs, ...}: {
  aos.system = {
    locale = "C.UTF-8";
    timezone = "UTC";
  };

  environment.systemPackages = [
    pkgs.curl
    pkgs.jq
  ];

  aos.firewall = {
    enable = true;
    defaultPolicy = "drop";
  };
}
```

Import it from each concrete variant. Reusable modules should use
`lib.mkDefault` where a concrete system is expected to override policy.

Registries needed from first boot can be seeded with their trust anchors:

```nix
{
  aos.apm.registries.acme = {
    url = "https://packages.example.com/";
    priority = 10;
    trustKeys = [
      "acme:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAA_REPLACE_ME"
    ];
  };
}
```

The image writes this read-only seed under `/etc/apm`; runtime changes use the
writable `/var/lib/apm/config` overlay.

## Build an image

The image pipeline targets `x86_64-linux` and `aarch64-linux` and produces a
raw GPT disk, QCOW2, VMDK, and dynamic VHD from the same evaluated system:

```sh
git add systems/acme-server.nix
nix-build -A systems.acme-server.build.toplevel
nix build .#acme-server-image-raw
nix build .#acme-server-image-qcow2
nix build .#acme-server-image-vmdk
nix build .#acme-server-image-vhd
```

Build the experimental artifacts from the same variant evaluation. The
`aos-experimental` variant defers image signing to the release finalizer, so Nix
stops at the unsigned assembly and publishes no `-image-<format>` outputs;
`aos maintain release step finalize-image` turns the assembly into the signed disks:

```sh
nix build .#aos-experimental-unsigned-image-assembly
nix build .#container-aos-experimental-oci
nix build .#container-aos-experimental-docker
nix build .#container-aos-experimental-publication-inputs
```

From another architecture, use an x86 Linux remote builder and select the
package set explicitly:

```sh
nix build .#packages.x86_64-linux.acme-server-image-qcow2
```

The raw output contains `aos-<system>.img.zst` and `image-info.json`. The outer
zstd stream keeps fixed partition headroom and the empty inactive slot out of
the transfer while the metadata separately binds both the compressed object
and reconstructed GPT disk. Secure Boot plus dm-verity systems also expose
`system.build.recoveryBootExecutableA`,
`system.build.recoveryBootExecutableB`, and `system.build.recoveryBundle`. The bundle has a
fixed `aos/recovery/` layout containing the ten cataloged payload components,
the db-signed manifest, and its detached signature. Preserve it with the
release if removable-media recovery is supported. Converted outputs contain
the corresponding disk file. Preserve the image metadata with every
distributed format.

The raw-image builder calculates ESP capacity from the installed normal and
recovery set plus one complete inactive-slot transaction. Inspect
`espBudget.installedBytes`, `espBudget.transactionBytes`,
`espBudget.requiredBytes`, and `espBudget.partitionBytes` in `image-info.json`
when changing UKI contents or recovery tooling; a build fails instead of
silently producing an ESP that cannot stage the transaction.

## Configure verified boot

Secure Boot, lockdown, and measured boot are opt-in per variant under
`aos.boot.secureBoot`. The base image owns no key, so a variant that enables
them must supply its own key material:

| Option | Purpose |
| --- | --- |
| `enable`, `dbCert` | Sign systemd-boot and UKIs; the public db certificate is baked into the image |
| `dbKey` | Private db key for in-build signing; forbidden under external finalization |
| `enrollAuthDir` | Public `db.auth`, `KEK.auth`, and `PK.auth` for `aos-sb-enroll` |
| `lockdown.enable`, `lockdown.mode` | Lockdown kernel with enforced module signing and signed kexec |
| `lockdown.moduleSigningKey` or `lockdown.moduleSigningCert` | In-build module key, or the public certificate for external signing |
| `measuredBoot.enable`, `measuredBoot.pcrPublicKey` | Signed PCR policy and TPM-sealed `/var` |
| `measuredBoot.pcrPrivateKey` | Private PCR-policy key for in-build signing |
| `measuredBoot.signedPcrs`, `measuredBoot.pinnedPcrs` | PCR selection; defaults `11` and `7+12` |
| `externalFinalization.enable` | Emit an unsigned assembly and obtain all signatures from external role-bound signers |

Recovery UKIs (`aos.boot.recovery.enable`) follow automatically when Secure
Boot and `aos.security.verity.enable` are both on. External finalization
requires lockdown, measured boot, recovery, and dm-verity together.

In-build signing copies the private keys into the builder's Nix store and is
suitable only for disposable test or staging identities. Production variants
use external finalization with `aos maintain release step finalize-image`, as
described in the [canonical release runbook](canonical-releases.md). The
`systems/server-secureboot*.nix` and `systems/server-measured-boot.nix`
fixtures use public test keys and must not be enrolled on real hardware.
Implementation details are in [Secure Boot](../engineering/boot/secure-boot.md)
and [Measured boot](../engineering/boot/measured-boot.md).

## Validate the release artifact

Build the variant's image contract check before publishing it:

```sh
nix-build -A systems.acme-server.checks.image-budget
cat result/report.json
```

Every discovered system exposes this check. It builds the root, initrd, UKI,
runtime closure, and compressed raw image; fails if any declared maximum is
exceeded; and writes the observed and maximum values to `report.json`.
Building each publication artifact independently enforces the complete
contract, records it in the integrity-bound `image-info.json`, and uses the
declared storage maxima for partition geometry. The resulting logical GPT disk
must also remain within the 8 GiB publication safety limit, which bounds image
materialization before any compressed bytes are expanded. Increase a budget
only as an intentional storage-format compatibility change; do not raise one
merely to absorb an unexplained size regression. Migrate existing storage
before deploying a payload that depends on larger root, verity, or ESP maxima.
Use `aos profile closure systems.acme-server.build.toplevel` to attribute
closure growth first.

UKI assembly and signing tools execute on the build platform. The EFI stub
and kernel match the target architecture, and runtime PE inspection uses the
small target-hosted `pe-tools` package without retaining the full binutils.
AArch64's uncompressed kernel makes its UKIs larger than the x86_64 images:

| Default maximum (MiB) | x86_64 | AArch64 |
| --- | ---: | ---: |
| UKI | 160 | 192 |
| ESP, including update workspace | 384 | 416 |
| Runtime NAR closure | 768 | 896 |

Recovery-enabled Secure Boot fixtures use ESP maxima of 544 MiB on x86_64
and 768 MiB on AArch64, retaining both recovery copies throughout an update.
The `server-2` HTTP fixture uses runtime closure maxima of 832 and 960 MiB,
respectively, and an 800 MiB download ceiling to accommodate its x86_64 VHD.
Development payload and forbidden-artifact checks remain the same on both
architectures.

The server and edge golden images cap compressed raw downloads at 768 MiB
with `maxDownloadMiB`. The uncompressed qcow2, VMDK, and VHD encodings use
`maxConvertedDownloadMiB`, which defaults to the raw limit. Secure Boot test
fixtures allow 800 MiB compressed raw because their recovery UKIs remain in
the disk. The diagnostic server-test images also allow 800 MiB compressed raw
on both architectures. Converted limits follow the measured target payloads:

| Converted maximum (MiB) | x86_64 | AArch64 |
| --- | ---: | ---: |
| Server and edge | 768 | 801 |
| Server-2 | 800 | 832 |
| Diagnostic server-test | 832 | 896 |
| Secure Boot and recovery fixtures | 896 | 1024 |

The compressed recovery archive has its own `maxRecoveryBundleMiB` limit,
defaulting to the raw limit for existing systems. It includes the root and
both normal and recovery UKIs, so the experimental release uses 1024 MiB on x86_64
and 1280 MiB on AArch64. These limits do not widen the raw or converted disk
budgets.

Each format manifest records its own limit in `artifactBudgetsMiB.download`.
Profile the closure and artifacts before changing either ceiling.

Inspect the evaluated option before building:

```sh
nix-instantiate --eval --strict \
  -A systems.acme-server.config.aos.networking.hostName
```

Boot the exact disk artifact that will be published and check at least:

```sh
systemctl is-system-running
systemctl --failed
systemctl status sshd.service
systemctl status nftables.service
cat /etc/hostname
cat /etc/ssh/sshd_config
cat /etc/nftables.conf
```

The [source-build tutorial](source-build-quickstart.md) supplies the AOS-built
QEMU, OVMF, metadata ISO, and a complete UEFI boot command. The
[deployment guide](../users/aos/deployment.md) covers qualification and
promotion of the resulting immutable artifact.

## Install redundant encrypted ZFS storage

> [!NOTE]
> ZFS is supported when configured, at the lowest of the
> [filesystem support tiers](../users/aos/support-status.md#filesystem-support-tiers).
> OpenZFS is an out-of-tree module whose Linux integration has produced memory
> retention, write stalls, and kernel panics on large hosts that no
> configuration bounds. Prefer the
> [ext4 layout](../users/aos/installation.md) unless a deployment needs
> ZFS features, and qualify ZFS on the exact host and kernel first.

The reusable `aos.profiles.bareMetalZfs` profile provides a different
bare-metal layout. Every selected disk receives an independently bootable ESP
sized from the golden image's artifact contract and a ZFS member. Adjacent
members form mirrors, and the mirrors are striped by the pool, so two disks
produce a mirror and four or more disks produce RAID10-style storage. The
encrypted pool contains mutable datasets and contract-sized zvols for both
immutable EROFS roots and both dm-verity hash trees. There is no LUKS layer
below ZFS.

Create a deployment system module from the production server baseline, enable
dm-verity and measured boot, enable the profile, list one ESP identity per
target disk, and supply deployment-owned Secure Boot and PCR-policy keys. Do
not import the checked-in Secure Boot or measured-boot system fixtures: those
also select test-only packages and keys. For example:

```nix
{
  imports = [./systems/server.nix];

  aos.security.verity.enable = true;

  aos.profiles.bareMetalZfs = {
    enable = true;
    espDevices = [
      "/dev/disk/by-partlabel/aos-esp-1"
      "/dev/disk/by-partlabel/aos-esp-2"
      "/dev/disk/by-partlabel/aos-esp-3"
      "/dev/disk/by-partlabel/aos-esp-4"
    ];
    nvidiaOpen = true;
    serverManagement = true;
  };

  # These values must be Nix path values from a private deployment input or
  # an isolated signing builder, not untracked absolute-path strings.
  aos.boot.secureBoot = {
    enable = true;
    dbKey = toString ./private-signing/db.key;
    dbCert = toString ./private-signing/db.crt;
    enrollAuthDir = toString ./public-enrollment;
    measuredBoot = {
      enable = true;
      pcrPrivateKey = toString ./private-signing/pcr.key;
      pcrPublicKey = toString ./public-signing/pcr.pem;
    };
  };
}
```

The private deployment input must be available to a controlled build sandbox;
these are Nix path values so their contents are copied into that builder's
store. Use a signing builder whose store, logs, and substituter outputs are not
shared, then destroy its private-key-bearing store paths after the build. Never
commit or publish the private input. The repository's measured-boot systems are
test fixtures with public keys; do not install them on a real machine.

The ZFS installation bundle below requires this in-build signing. To keep
private keys out of the Nix store entirely, use external finalization instead.
Set `aos.boot.secureBoot.externalFinalization.enable = true`, omit `dbKey`,
`lockdown.moduleSigningKey`, and `measuredBoot.pcrPrivateKey`, and supply only
public material: `dbCert`, `enrollAuthDir`, `lockdown.moduleSigningCert`, and
`measuredBoot.pcrPublicKey`. External finalization also requires lockdown,
measured boot, recovery, and dm-verity to be enabled. Nix then builds the
unsigned `system.build.unsignedImageAssembly` and no signed disk images or
installation bundle. `aos maintain release step finalize-image` signs that
assembly through an external signer process under a release plan and writes
the signed raw, QCOW2, VMDK, and VHD disks. The signer interface, the bundled
file-backed signer, and the full command are described in
[Finalize each Linux image](release-step-commands.md#finalize-each-linux-image).

Build the module's `system.build.installBundle` output on x86 Linux. Run the
bundle's `bin/aos-install-zfs` from a trusted AOS recovery environment that has the exact ZFS
kernel module loaded, the deployment Secure Boot keys enrolled, Secure Boot
enforcing, and a working TPM2. The command is intentionally destructive and
accepts only stable whole-disk identities with no existing partition table:

```sh
/path/to/install-bundle/bin/aos-install-zfs \
  --confirm ERASE-AND-INSTALL \
  --recovery-key-output /recovery-media/zfs-recovery.key \
  --disk /dev/disk/by-id/REPLACE_WITH_DISK_1 \
  --disk /dev/disk/by-id/REPLACE_WITH_DISK_2 \
  --disk /dev/disk/by-id/REPLACE_WITH_DISK_3 \
  --disk /dev/disk/by-id/REPLACE_WITH_DISK_4
```

The number of `--disk` arguments must equal the configured ESP count and must
be even. Before the first destructive write, the installer rejects duplicate,
mounted, partitioned, or kernel-name-only disks; an existing or relative
recovery output; a topology mismatch; and a non-enforcing Secure Boot state.
It creates native AES-256-GCM encryption, verifies the root payloads fit their
zvol capacities, seals the pool key to the configured PCR policy, copies the
sealed credential and boot artifacts to every ESP, and exports the pool.

Move the recovery key off the installation environment before rebooting. Test
both unattended TPM unlock and recovery-key import, then test booting through
each firmware-visible ESP and surviving one failed mirror member before
placing data on the system.

Kernel lockdown is a separate opt-in policy. If enabled, the deployment must
also sign both the ZFS and NVIDIA external modules with a key trusted by the
kernel; the bare-metal profile does not generate or retain that private key.

## Image definition limits

These limits apply when defining and building an image. Limits that an
operator meets at installation time are in
[Installation limits](../users/aos/installation.md#installation-limits).

- The ZFS installer supports mirrored pairs striped into RAID10-style pools.
  RAID0-only topology is intentionally not exposed because it cannot satisfy
  the redundant-storage contract.
- The initrd carries a focused firmware subset for supported pre-root server
  storage and network adapters, not the general runtime bundle. Image
  definitions for other hardware must add the required firmware package to
  `aos.boot.initrd.firmwarePackages`; runtime firmware remains available after
  the immutable root is mounted.
- Set `aos.kernel.includeFirmware = false` in the image definition to omit
  device firmware from both the initrd and immutable root. The default is
  `true`. The existing firmware package lists select which files are included
  when the flag is enabled. NVIDIA open kernel modules require it enabled.
- NVIDIA support in this repository stops at open kernel modules and matching
  GSP firmware. CUDA, OpenGL, Vulkan, management utilities, and other matching
  proprietary userspace components must be supplied separately.
- Installer media is built only for locally signed Secure Boot systems. The
  production external-finalization path does not yet produce it.
