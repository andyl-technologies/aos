# lib/testing/fleet-spec.nix — Typed schema for tests/fleet/*.nix
#
# Each spec file under `tests/fleet/` is a function of `{ lib, pkgs,
# systems }` returning one attrset; the discoverer in `default.nix`
# evaluates the attrset against `fleetSpecType` here so eval-time
# mistakes (typos in field names, malformed ignition, package-name typos)
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

  ignitionFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = false;
  };

  # Image-boot machines run ignition's disks stage for real — their
  # instanceMetadata legitimately carries storage.disks /
  # storage.filesystems (that's the install). Kernel-boot machines keep
  # the restrictive profile.
  ignitionFullFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = true;
  };

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

      bootMode = mkOption {
        type = types.enum ["kernel" "image"];
        default = "kernel";
        description = ''
          How this machine boots. `kernel` (default) is the original
          fleet path: direct kernel boot (`-kernel`/`-initrd`) with the
          ignition config on a metadata ISO. `image` boots the
          machine's `system.build.image.raw` under OVMF — UEFI →
          sd-boot → UKI → ignition — with the ignition config delivered
          over `-fw_cfg name=opt/com.coreos/config` (no metadata ISO; the
          ISO would force PLATFORM_ID=file). Image machines accept the
          FULL ignition profile in `instanceMetadata.config`, including
          `storage.disks`/`storage.filesystems` — exercising the
          first-boot install path is the point
          (tests/fleet/install-from-image.nix, RFC-0003).
        '';
      };

      imageDiskMiB = mkOption {
        type = positiveInt;
        default = 40960;
        description = ''
          Image-boot machines only: size in MiB the per-run copy of the
          raw image is grown to before boot (sparse truncate +
          `sgdisk -e` backup-header relocation). Must be large enough
          for the partitions the machine's ignition `storage.disks`
          config declares; the docs' A/B layout (16 GiB root-a/root-b +
          4 GiB swap + var) needs the default 40 GiB.
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

      varSizeMiB = mkOption {
        type = positiveInt;
        default = 256;
        description = ''
          Size of this machine's /var partition in MiB. The default fits
          per-test state; raise it for machines that stage large payloads
          under /var, e.g. a registry peer generating a static binary
          cache of a full system closure (tests/fleet/
          apm-registry-upgrade.nix).
        '';
      };

      instanceMetadata = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            format = mkOption {
              type = types.enum ["ignition"];
              default = "ignition";
            };
            config = mkOption {
              # Image-boot machines opt into the full profile (storage
              # hardware allowed); evaluated lazily, by which time
              # `config.bootMode` has merged.
              type =
                (
                  if config.bootMode == "image"
                  then ignitionFullFormat
                  else ignitionFormat
                )
                .type;
              default = {};
            };
          };
        });
        default = null;
        description = ''
          Raw ignition config delivered to this machine via the
          `aos-metadata` ISO.
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
