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

      instanceMetadata = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            format = mkOption {
              type = types.enum ["ignition"];
              default = "ignition";
            };
            config = mkOption {
              type = ignitionFormat.type;
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
