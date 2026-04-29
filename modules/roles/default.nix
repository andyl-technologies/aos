##! modules/roles/default.nix — Per-role typed ignition configurations.
##!
##! Declares the `aos.roles.<name>` option tree with strict ignition
##! types at the outer layer (no sub-`evalModules`), composes the final
##! `ignitionConfig` per role, and materialises each role's config to
##! its own derivation in the Nix store via
##! `lib.formats.ignition.generate`.
##!
##! Role files in this directory are auto-loaded by
##! `modules/default.nix`'s loader; the role module declares the
##! `aos.roles.<name>` value, and any side-effects it wants on a
##! locally-activated host go inside `lib.mkIf cfg.enable {…}`. Roles
##! whose `enable` flag is false still produce their `ignitionConfig`
##! and `ignitionConfigDrv`, so the image builder can ship JSON for
##! every defined role to every host (runtime-selectable by
##! `aos-bootstrap`).
{
  config,
  lib,
  pkgs,
  ...
}: let
  ignitionFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = false; # roles never own partitioning
  };
  jsonFormat = lib.formats.json {inherit lib pkgs;};

  systemdLib = import ../../lib/modules/systemd/lib.nix {inherit lib pkgs;};
  ignitionLib = import ../../lib/modules/ignition/systemd.nix {inherit lib pkgs;};

  T = ignitionLib.toIgnitionUnit;

  renderRoleSystemd = sd:
    lib.mapAttrsToList (_: T systemdLib.serviceToUnit) sd.services
    ++ lib.mapAttrsToList (_: T systemdLib.targetToUnit) sd.targets
    ++ lib.mapAttrsToList (_: T systemdLib.socketToUnit) sd.sockets
    ++ lib.mapAttrsToList (_: T systemdLib.timerToUnit) sd.timers
    ++ lib.mapAttrsToList (_: T systemdLib.pathToUnit) sd.paths
    ++ lib.mapAttrsToList (_: T systemdLib.sliceToUnit) sd.slices
    ++ builtins.map (T systemdLib.mountToUnit) sd.mounts
    ++ builtins.map (T systemdLib.automountToUnit) sd.automounts;

  # Filesystem-safe role names: lowercase letters, digits, dashes,
  # starting with a letter. Used as both the derivation `pname` and
  # the file inside `ignitionFormat.generate`'s output, so anything
  # else risks colliding with another role or breaking the image's
  # symlink layout.
  roleNamePattern = "[a-z][a-z0-9-]*";

  roleType = lib.types.submodule ({
    name,
    config,
    ...
  }: {
    options = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Whether this role's runtime side effects (its
          `environment.systemPackages` contributions, its
          `system.checks` registrations, any `aos.services.*` flips)
          take effect on this host. Profiles activate roles by
          flipping this to `true`. The role's `ignitionConfig` and
          `ignitionConfigDrv` are computed regardless — the image
          builder ships them to every host that imports the role
          file, since `aos-bootstrap` may select a role at runtime
          based on userdata even on hosts that don't activate it
          locally.
        '';
      };

      # Typed systemd inputs — strict types from the ignition lib so
      # eval-time errors surface at the role's def site, not one
      # level deeper in a nested module evaluation.
      systemd = {
        services = lib.mkOption {
          type = ignitionLib.ignitionServices;
          default = {};
        };
        targets = lib.mkOption {
          type = ignitionLib.ignitionTargets;
          default = {};
        };
        sockets = lib.mkOption {
          type = ignitionLib.ignitionSockets;
          default = {};
        };
        timers = lib.mkOption {
          type = ignitionLib.ignitionTimers;
          default = {};
        };
        paths = lib.mkOption {
          type = ignitionLib.ignitionPaths;
          default = {};
        };
        slices = lib.mkOption {
          type = ignitionLib.ignitionSlices;
          default = {};
        };
        mounts = lib.mkOption {
          type = ignitionLib.ignitionMounts;
          default = [];
        };
        automounts = lib.mkOption {
          type = ignitionLib.ignitionAutomounts;
          default = [];
        };
      };

      # Storage / files / users / kernelArguments that ignition should
      # write directly. Escape hatch for roles whose needs go beyond
      # systemd units (e.g. k3s wants /etc/rancher/k3s/config.yaml).
      ignitionExtras = lib.mkOption {
        type = ignitionFormat.type;
        default = {};
      };

      # Per-role bootstrap-time inputs the operator must fill. Typed
      # via `lib.formats.json` — strict enough to reject anything
      # `builtins.toJSON` can't round-trip, lets `aos-bootstrap` parse
      # the schema directly without inventing its own format. Use
      # nested attrsets to describe the expected shape.
      userDataSchema = lib.mkOption {
        type = jsonFormat.type;
        default = {};
        description = ''
          Typed shape (key → expected type) describing the per-host
          inputs `aos-bootstrap` fills before applying this role.
          Conventional shape: an attrset where each leaf is a string
          naming a primitive type (e.g. `{ apiserverEndpoint =
          "string"; nodeIndex = "int"; }`).
        '';
      };

      # Computed: the ignition config to ship.
      ignitionConfig = lib.mkOption {
        type = ignitionFormat.type;
        readOnly = true;
        internal = true;
        description = "Final Ignition config for this role.";
      };

      # Computed: a derivation whose output is `$out/<role-name>` —
      # the validated ignition JSON. The image builder symlinks each
      # of these into a stable image path (e.g.
      # /etc/aos/ignition-roles/<role-name>.json) so `aos-bootstrap`
      # can resolve `userdata`-selected role names at runtime.
      ignitionConfigDrv = lib.mkOption {
        type = lib.types.package;
        readOnly = true;
        internal = true;
        description = "Materialised + validated Ignition config for this role.";
      };
    };

    config = {
      # Merge the role's typed systemd inputs with `ignitionExtras`
      # as a single definition. `lib.mkMerge` would expand into two
      # separate option defs, which trips `readOnly = true`'s
      # multiple-definition guard. Shallow `//` is enough because we
      # only rewrite `systemd` — the other ignition top-level fields
      # (`storage`, `passwd`, …) ride through extras unchanged. Within
      # `systemd`, we splice into the existing `units` list (preserving
      # any escape-hatch units the role wrote into
      # `ignitionExtras.systemd.units`).
      ignitionConfig = let
        extras = config.ignitionExtras;
        extrasSystemd = extras.systemd or {};
        extrasUnits = extrasSystemd.units or [];
        roleUnits = renderRoleSystemd config.systemd;
      in
        extras
        // {
          systemd =
            extrasSystemd
            // {
              units = extrasUnits ++ roleUnits;
            };
        };
      ignitionConfigDrv = ignitionFormat.generate name config.ignitionConfig;
    };
  });

  # Lift per-role assertions to the top-level `assertions` option
  # (declared in modules/base/build.nix:50). Submodule-level
  # `config.assertions` doesn't propagate — only the outer module's
  # top-level `config.assertions` is consumed by build.nix's
  # toplevel-failed-assertions check.
  #
  # `ignitionExtras` is typed as `ignitionFormat.type` (a strict
  # submodule), but AOS's modules engine returns the literal `default
  # = {}` when no defs exist — it doesn't run defaults through the
  # submodule type. So `role.ignitionExtras.systemd` is missing when
  # the role doesn't override extras. Read defensively with `or
  # null`, and `nullSubmodule systemdType` makes the populated case
  # `null` too unless the user actually wrote `ignitionExtras.systemd
  # = { units = […]; }`.
  roleAssertions = name: role: let
    renderedNames = builtins.map (u: u.name) (renderRoleSystemd role.systemd);
    extraSystemd = role.ignitionExtras.systemd or null;
    extraNames =
      builtins.map (u: u.name)
      (lib.optionals (extraSystemd != null) extraSystemd.units);
    collisions = builtins.filter (n: builtins.elem n renderedNames) extraNames;
  in [
    {
      assertion = builtins.match roleNamePattern name != null;
      message = ''
        aos.roles."${name}": role names must match
        ${roleNamePattern} (lowercase letters, digits, dashes;
        starting with a letter). The name is used both as the
        derivation `pname` and as the filename inside
        ignitionConfigDrv's output.
      '';
    }
    {
      assertion = collisions == [];
      message = ''
        aos.roles."${name}": unit name collision between
        typed systemd inputs and ignitionExtras.systemd.units:
        ${lib.concatStringsSep ", " collisions}.
        Move one side or rename to avoid a late
        ignition-validate failure.
      '';
    }
  ];
in {
  options = {
    aos.roles = lib.mkOption {
      type = lib.types.attrsOf roleType;
      default = {};
    };

    system.build.ignitionRolesBundle = lib.mkOption {
      type = lib.types.package;
      description = ''
        Derivation whose output is a flat directory of `<role-name>`
        symlinks, one per `aos.roles.<name>`, each pointing at the
        role's pre-validated Ignition JSON inside its own
        `ignitionConfigDrv`. Consumed by the cpio assembler in
        `modules/base/_initrd-builder.nix` (which symlinks
        `/etc/aos/ignition-roles → ${"\${ignitionRolesBundle}"}`
        inside the initrd) and by `environment.etc."aos/ignition-roles"`
        below (which surfaces the same path in stage-2 /etc).
      '';
    };
  };

  config = {
    assertions =
      lib.concatLists
      (lib.mapAttrsToList roleAssertions config.aos.roles);

    # Bundle: a single derivation whose `$out` is a flat directory of
    # `<role-name>` symlinks pointing at each role's pre-validated JSON.
    # Stable filename per role (the role's name) → operator-visible URL
    # `file:///etc/aos/ignition-roles/<role-name>` is rebuild-stable
    # even though the bundle drv's hash isn't.
    #
    # Empty-roles edge case: `lib.mapAttrsToList` over an empty attrset
    # produces `[]`, the `for`-equivalent loop emits no `ln` lines, and
    # the resulting derivation is an empty directory. That is correct:
    # a host with no roles defined still gets a working symlink target,
    # just one with nothing inside.
    #
    # Closure tracking note: Nix scans the bundle drv's `$out` for
    # `/nix/store/...` substrings to compute its references. The
    # symlinks we lay down contain those store paths as their target
    # text, so each role's `ignitionConfigDrv` is pulled into the
    # bundle's closure transparently. The initrd-builder's
    # `exportReferencesGraph` addition then drags the whole closure into
    # the initrd's `/nix/store`. If this derivation ever changes from
    # "directory of symlinks" to something that doesn't embed target
    # paths as text (e.g. a tar archive), the closure-tracking has to
    # be re-established explicitly via `runtimeDeps` or similar.
    system.build.ignitionRolesBundle = pkgs.mkDerivation {
      pname = "aos-ignition-roles-bundle";
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils];
      phases = [
        {
          name = "assemble";
          script = ''
            mkdir -p "$out"
            ${lib.concatStringsSep "\n" (
              lib.mapAttrsToList (
                name: role:
                  "ln -sfn ${role.ignitionConfigDrv}/${name} \"$out/${name}\""
              )
              config.aos.roles
            )}
          '';
        }
      ];
    };

    # Stage-2 mirror at /etc/aos/ignition-roles → bundle. Same /nix/store
    # path is reachable from both initrd and stage-2; this `environment.etc`
    # entry installs the same symlink into the system /etc tree at toplevel
    # build time (see modules/base/build.nix:23 for how `source` entries
    # are realised).
    #
    # Operator value: post-boot `cat /etc/aos/ignition-roles/<role>` works
    # for inspection without duplicating bytes — the file content lives
    # once, in the role's `ignitionConfigDrv` output, and both paths are
    # symlinks to it.
    environment.etc."aos/ignition-roles" = {
      source = config.system.build.ignitionRolesBundle;
    };
  };
}
