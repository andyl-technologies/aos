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
# machine's chosen `system.config.aos.roles`. The type is forced
# lazily — only when a `roles` value is type-checked, by which time
# `config.system` has been merged from the user's definition.
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
        # Type-level enum derived from this machine's chosen system.
        # `availableRoles` is forced lazily — only when a `roles` value
        # is type-checked, by which time `config.system` has been
        # merged from the user's definition.
        type = let
          availableRoles =
            builtins.attrNames (config.system.config.aos.roles or {});
        in
          types.listOf (types.enum availableRoles);
        default = [];
        description = ''
          Names of `aos.roles.<name>` to activate on this machine. Each
          name is converted into a
          `{ source = "file:///etc/aos/ignition-roles/<name>"; }`
          entry on the machine's `ignition.config.merge` list. Roles
          are pre-baked into the image — no on-the-fly system
          re-evaluation.
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
      testScript = mkOption {type = types.lines;};
      timeout = mkOption {
        type = types.int;
        default = 300;
      };
    };
  };
in {
  inherit fleetSpecType fleetMachineType;
}
