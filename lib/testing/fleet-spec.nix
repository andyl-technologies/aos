# lib/testing/fleet-spec.nix — Typed schema for tests/fleet/*.nix
#
# Each spec file under `tests/fleet/` is a function of `{ lib, pkgs,
# systems }` returning one attrset; the discoverer in `default.nix`
# evaluates the attrset against `fleetSpecType` here so eval-time
# mistakes (typos in field names and package names)
# surface as `evalModules` errors rather than runtime failures inside
# the harness.
#
# `fleetMachineType.options.packages` derives its enum from this machine's
# chosen system config, filtered to entries where `bundle = true` on that
# system. Only bundled packages are listable: the payload and rendered expose
# artifact must already be baked into the machine image. The type is forced
# lazily — only when a value is type-checked, by which time `config.system` has
# been merged from the user's definition.
{
  lib,
  pkgs,
}: let
  inherit (lib) types mkOption;

  # `types.unspecified` (nixpkgs name): a no-op type that accepts any
  # value with `lastValue` merge. AOS's lib doesn't ship one, so we
  # synthesise it via `mkOptionType`'s defaults (check defaults to
  # accept-anything, merge defaults to lastValue). Used for `system`,
  # which is the evaluated system attrset (`{config, options, build,
  # checks}`); a structural check happens at the `mkFleetTest` use
  # site, not here.
  unspecifiedType = lib.mkOptionType {
    name = "unspecified";
    description = "any value";
  };

  positiveInt = types.addCheck types.int (v: v > 0);

  fleetMachineType = types.submodule ({config, ...}: {
    options = {
      system = mkOption {
        type = unspecifiedType;
        description = ''
          The evaluated system attrset (e.g. `systems.server` in the
          discovered top-level `systems` attrset). The harness reads
          `.config.system.build.{kernel,initrd}` and `.config.aos.packages`
          off this value; passing anything else fails fast with a clear
          message at the use site.
        '';
      };

      packages = mkOption {
        type = let
          availablePackages = builtins.attrNames (
            lib.filterAttrs
            (_: package: package.bundle)
            (config.system.config.aos.packages or {})
          );
        in
          types.listOf (types.enum availablePackages);
        default = [];
        description = ''
          Names of `aos.packages.<name>` to activate at runtime on this
          machine. Each package must have `bundle = true` on the chosen
          system so the package payload and rendered expose artifact are
          already present in the image. The fleet harness seeds the
          per-machine system package profile before stage 2, and APM
          reconciliation attaches and presets the selected package target.
        '';
      };

      extraModules = mkOption {
        type = types.listOf unspecifiedType;
        default = [];
        description = ''
          Extra NixOS-style module fragments overlaid onto this machine's
          system via `extendModules`. The mechanism the fleet
          harness uses to bake per-VM configuration into the image `/etc` in
          place of runtime file injection — e.g. a k3s node's
          `/etc/rancher/k3s/config.yaml` and token env.
        '';
      };

      metadata = mkOption {
        type = types.attrsOf types.str;
        default = {};
        description = ''
          Files exposed to the initrd on a read-only ISO labelled
          `aos-metadata`. Attribute names are plain file names such as
          `host.nix` and values are their exact contents. Use this
          to exercise the production cloud-metadata provisioning path.
        '';
      };

      bootMode = mkOption {
        type = types.enum ["kernel" "image"];
        default = "kernel";
        description = ''
          How this machine boots. `kernel` (default) is direct kernel boot
          (`-kernel`/`-initrd`); /var is a baked test disk, so no on-boot
          disk carving is needed. `image` boots the machine's
          `system.build.image.raw` under OVMF — UEFI → sd-boot → UKI →
          systemd initrd — where systemd-repart carves swap/var from the
          trailing free space on first boot (tests/fleet/install-from-image.nix,
          image installation tests).
        '';
      };

      imageDiskMiB = mkOption {
        type = positiveInt;
        default = 40960;
        description = ''
          Image-boot machines only: size in MiB the per-run copy of the
          raw image is grown to before boot (sparse truncate +
          `sgdisk -e` backup-header relocation). Must be large enough for
          the partitions systemd-repart carves in the trailing free space
          (swap + var); the default 40 GiB has ample headroom.
        '';
      };

      extraClosures = mkOption {
        type = types.listOf types.package;
        default = [];
        description = ''
          Extra Nix derivations whose full closures land in /nix/store on
          this machine's rootfs. Used by upgrade tests that need a second
          system toplevel pre-staged on disk so `apm upgrade --system`
          doesn't have to traverse the network for store paths (the
          pre-staged path is registered valid in the Nix DB at test time;
          see tests/fleet/apm-system-upgrade.nix).
        '';
      };

      tpm = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Attach an emulated TPM 2.0 (swtpm) to this machine. The driver
          launches a swtpm process per machine and wires QEMU's
          `tpm-tis` device to it over a control socket. Needed by
          measured-boot tests (RFC-0006 phase 3); harmless otherwise.
        '';
      };

      memoryMiB = mkOption {
        type = positiveInt;
        default = 2048;
        description = ''
          RAM in MiB handed to this machine's QEMU (`-m`). The default
          fits a full systemd boot plus the role under test; the
          gzip-compressed initrd unpacks into a tmpfs that is freed at
          switch-root, so peak boot footprint stays well under it. Raise
          it only for machines that run a memory-hungry workload in the
          guest (e.g. a k3s control plane). Lower it for lean single-role
          machines where host RAM is the constraint and many VMs run at
          once. Both the sandboxed driver and the interactive launcher
          honor this value.
        '';
      };

      varSizeMiB = mkOption {
        type = positiveInt;
        default = 256;
        description = ''
          Size of this machine's /var partition in MiB. The default fits
          per-test state; raise it for machines that stage large payloads
          under /var, e.g. a registry peer generating a static binary
          cache of a full system closure (tests/fleet/
          apm-registry-upgrade.nix). With `varProvisioning = "baked"`
          (the default) this sizes the partition baked into the disk image;
          with `varProvisioning = "repart"` it is the size the driver grows
          the per-run disk by, into which systemd-repart carves /var at first
          boot.
        '';
      };

      varProvisioning = mkOption {
        type = types.enum ["baked" "repart"];
        default = "baked";
        description = ''
          How this machine's /var comes to exist (kernel-boot machines
          only). `baked` (default) ships /var as a pre-formatted, seeded
          partition inside the disk image. `repart` ships no /var partition:
          the driver grows the per-run copy by `varSizeMiB`, and
          systemd-repart carves /var (and swap) in the trailing free space at
          first boot. With no baked /var seed the guest agent arrives via a
          baked `systemd.services.aos-test-agent` unit — the harness adds that
          package automatically (lib/testing/fleet.nix), so tests need not
          list it.
        '';
      };
    };
  });

  fleetSpecType = types.submodule {
    options = {
      name = mkOption {type = types.str;};
      machines = mkOption {type = types.attrsOf fleetMachineType;};
      testScript = mkOption {
        type = types.lines;
        description = ''
          Python fragment run by the AOS test driver
          (pkgs/tools/aos/aos-test-driver) once every machine's agent
          is reachable. Each machine is exposed as a Python global
          named after its attribute key (e.g. `controlplane`,
          `worker`); call `controlplane.succeed("...")`,
          `controlplane.wait_until_succeeds("...", timeout=60)`,
          etc. — see
          `pkgs/tools/aos/aos-test-driver/aos_test_driver/machine.py`
          for the full Machine API.
        '';
      };
      timeout = mkOption {
        type = types.int;
        default = 300;
      };
      bootTimeout = mkOption {
        type = types.nullOr types.int;
        default = null;
        description = ''
          Per-boot budget (seconds) for a machine's agent to answer after
          (re)launch, overriding the driver default. Raise it for boots
          that are legitimately slow — e.g. measured boot, where the
          emulated TPM adds tens of seconds of slow command round-trips
          per boot. Null uses the driver default.
        '';
      };
    };
  };
in {
  inherit fleetSpecType fleetMachineType;
}
