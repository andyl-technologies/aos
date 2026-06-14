# lib/testing/fleet-spec.nix — Typed schema for tests/fleet/*.nix
#
# Each spec file under `tests/fleet/` is a function of `{ lib, pkgs,
# systems }` returning one attrset; the discoverer in `default.nix`
# evaluates the attrset against `fleetSpecType` here so eval-time
# mistakes (typos in field names, malformed ignition, role-name typos)
# surface as `evalModules` errors rather than runtime failures inside
# the harness.
#
# `fleetMachineType.options.roles`'s `enum` is derived from this
# machine's chosen `system.config.aos.roles`, filtered to roles where
# `bundle = true` on that system — only bundled roles are listable,
# since a role not bundled on the host has no ignition fragment at
# `/etc/aos/ignition-roles/<name>` for the synthesised merge entry to
# point at. The type is forced lazily — only when a `roles` value is
# type-checked, by which time `config.system` has been merged from the
# user's definition.
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
          `.config.system.build.{kernel,initrd}` and `.config.aos.roles`
          off this value; passing anything else fails fast with a clear
          message at the use site.
        '';
      };

      roles = mkOption {
        # Type-level enum derived from this machine's chosen system,
        # restricted to roles where `bundle = true` — only bundled
        # roles have a fragment at `/etc/aos/ignition-roles/<name>` on
        # the running host for the synthesised
        # `ignition.config.merge` entry to resolve. `availableRoles`
        # is forced lazily — only when a `roles` value is type-checked,
        # by which time `config.system` has been merged from the
        # user's definition.
        type = let
          availableRoles = builtins.attrNames (
            lib.filterAttrs
            (_: role: role.bundle)
            (config.system.config.aos.roles or {})
          );
        in
          types.listOf (types.enum availableRoles);
        default = [];
        description = ''
          Names of `aos.roles.<name>` to activate at runtime on this
          machine. Each name is converted into a
          `{ source = "file:///etc/aos/ignition-roles/<name>"; }`
          entry on the machine's `ignition.config.merge` list. The
          listed roles must have `bundle = true` on the chosen system
          — otherwise the fragment is not on disk and the merge would
          fail at first boot.
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
          `aos-metadata` ISO. If both `roles` and
          `instanceMetadata.config.ignition.config.merge` are populated,
          the harness prepends role merge entries to the
          test-supplied merge list.
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
    };
  };
in {
  inherit fleetSpecType fleetMachineType;
}
