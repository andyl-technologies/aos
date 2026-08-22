# Build and customize release images

This guide is for AOS release maintainers and platform integrators. End users
should download the published AOS image, customize the host with `host.nix`,
and install packages with `apm`.

Runtime `host.nix` activation evaluates and atomically applies networking,
users, access, services, packages, and other general host policy. Keep only
image capabilities, bootstrap reachability, and initial trust roots in the
release image; put machine-specific policy in authenticated `host.nix`.

## Create a system variant

Files under `systems/` are discovered automatically. A file named
`systems/acme-server.nix` produces an evaluated system at
`systems.acme-server` and image outputs named `acme-server-image-<format>`.

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
    maxUkiMiB = 160;
    maxEspMiB = 384;
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

The image pipeline currently targets `x86_64-linux` and produces a raw GPT
disk, QCOW2, VMDK, and dynamic VHD from the same evaluated system:

```sh
git add systems/acme-server.nix
nix-build -A systems.acme-server.build.toplevel
nix build .#acme-server-image-raw
nix build .#acme-server-image-qcow2
nix build .#acme-server-image-vmdk
nix build .#acme-server-image-vhd
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
`system.build.recoveryUkiA`,
`system.build.recoveryUkiB`, and `system.build.recoveryBundle`. The bundle has a
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

The server and edge golden images cap each directly downloadable encoding at
640 MiB with `maxDownloadMiB`. Treat a transfer-budget failure as a release-size
regression: profile the closure and artifacts before changing that ceiling.

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
