##! modules/roles/default.nix — Per-role typed ignition configurations.
##!
##! Declares the `aos.roles.<name>` option tree with strict ignition
##! types at the outer layer (no sub-`evalModules`), composes the final
##! `ignitionConfig` per role, and materialises each role's config to
##! its own derivation in the Nix store via
##! `lib.formats.ignition.generate`.
##!
##! Role files in this directory are auto-loaded by
##! `modules/default.nix`'s loader; each role module declares the
##! `aos.roles.<name>` value (typed systemd/kernel/firewall inputs +
##! `ignitionExtras`) unconditionally, and any host-local payload
##! (`environment.systemPackages`, `system.checks`, `aos.services.*`)
##! goes inside `lib.mkIf cfg.bundle {…}`.
##!
##! `bundle` is the single per-host inclusion flag. When true, the
##! role is **bundled into the image**: its `ignitionConfigDrv` is
##! materialised, its entry lands in `system.build.ignitionRolesBundle`
##! at `/etc/aos/ignition-roles/<name>`, the role's unit-file closure
##! is pulled into the image, and the host-local payload is baked in.
##! When false, none of that is bundled — the role's module is still
##! loaded (so eval-time assertions and the fleet-spec enum can
##! introspect it) but the role is not available on this host.
##!
##! Bundling a role makes it **available** to activate at runtime; it
##! does not activate it. Activation happens only when the role's
##! ignition fragment is merged into the host's ignition config at
##! first boot, via `ignition.config.merge` in the instance metadata
##! (cloud-init userdata, IPMI virtual media, or — in fleet tests —
##! the per-machine `roles = [...]` shorthand in
##! `lib/testing/fleet.nix`, which synthesises the same merge entry).
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

  # Renders a role's typed systemd inputs into a `generateUnits`-style
  # derivation plus the eval-time prediction of `storage.links`
  # entries that ignition's files stage will lay down inside the
  # per-gen lower's `/etc/systemd/system/...` subtree. See spec v12
  # §5.6 and `lib/modules/systemd/render-role.nix` for the contract.
  renderRole = import ../../lib/modules/systemd/render-role.nix {
    inherit lib pkgs systemdLib;
  };

  # Filesystem-safe role names: lowercase letters, digits, dashes,
  # starting with a letter. Used as both the derivation `pname` and
  # the file inside `ignitionFormat.generate`'s output, so anything
  # else risks colliding with another role or breaking the image's
  # symlink layout.
  roleNamePattern = "[a-z][a-z0-9-]*";

  # Render a role's `kernel` / `firewall` config into its
  # `storage.links` list (≤3 entries). Each drop-in file is
  # materialised as its own `pkgs.writeTextFile` derivation and
  # surfaced as an ignition symlink whose `target` is that store
  # path. An entry is emitted only when its source option is
  # non-empty.
  #
  # The file is written at `<drv>/<basename>` via a non-empty
  # `destination`: AOS's stdenv `setup.sh` always pre-creates `$out`
  # as a directory, so the empty-destination "`$out` *is* the file"
  # mode does not work here — the content would land *inside* the
  # directory. The store path still holds the content exactly once;
  # the link `target` just carries the basename.
  #
  # The drop-in derivations' store paths end up as
  # `storage.links[].target` strings in `ignitionConfigDrv`'s JSON,
  # so they carry string context into the bundle's closure — see the
  # closure-tracking note on `ignitionRolesBundle` below.
  renderRoleLinks = name: role: let
    portList = ports: builtins.concatStringsSep ", " (builtins.map builtins.toString ports);

    # `path` is an ordinary /etc/... path; ignition's --root=/sysroot
    # plus ignition-files.service's /var/etc BindPaths land it on the
    # rw /var partition, where the /etc overlay surfaces it in stage-2.
    # The drop-in's basename is reused as the derivation's
    # `destination`, so `target` resolves to `<drv>/<basename>`.
    mkLink = path: text: let
      file = builtins.baseNameOf path;
      drv = pkgs.writeTextFile {
        name = file;
        destination = "/${file}";
        inherit text;
      };
    in {
      inherit path;
      target = "${drv}/${file}";
      overwrite = true;
    };

    modulesLink = lib.optional (role.kernel.modules != []) (
      mkLink "/etc/modules-load.d/role-${name}.conf" (
        lib.concatMapStrings (m: "${m}\n") role.kernel.modules
      )
    );

    sysctlLink = lib.optional (role.kernel.sysctl != {}) (
      mkLink "/etc/sysctl.d/70-role-${name}.conf" (
        lib.concatStrings (
          lib.mapAttrsToList (k: v: "${k} = ${v}\n") role.kernel.sysctl
        )
      )
    );

    fw = role.firewall;
    fwActive =
      fw.allowedTCP != [] || fw.allowedUDP != [] || fw.forwardPolicy == "accept";

    # Drop-in carries only `add` statements — the `inet filter` table
    # and the `allowed_*` sets are declared earlier in the same atomic
    # `nft -f` transaction (see modules/security/firewall.nix).
    nftLink = lib.optional fwActive (
      mkLink "/etc/nftables.d/50-role-${name}.nft" (
        "# /etc/nftables.d/50-role-${name}.nft — generated for aos.roles.${name}\n"
        + lib.optionalString (fw.allowedTCP != [])
        "add element inet filter allowed_tcp { ${portList fw.allowedTCP} }\n"
        + lib.optionalString (fw.allowedUDP != [])
        "add element inet filter allowed_udp { ${portList fw.allowedUDP} }\n"
        + lib.optionalString (fw.forwardPolicy == "accept")
        "add rule inet filter forward accept\n"
      )
    );
  in
    modulesLink ++ sysctlLink ++ nftLink;

  roleType = lib.types.submodule ({
    name,
    config,
    ...
  }: {
    options = {
      bundle = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Whether this role is bundled into the image. When true, its
          ignition fragment is materialised at
          `/etc/aos/ignition-roles/<name>` (via
          `system.build.ignitionRolesBundle`), the unit-file closure
          is pulled into the image, and any host-local payload —
          `environment.systemPackages` contributions, `system.checks`
          registrations, `aos.services.*` flips — is baked in. When
          false, the role's module is loaded but nothing is bundled
          and the role cannot be activated on this host.

          Bundling makes the role **available** to activate at
          runtime; it does not activate it. Activation happens only
          when the role's ignition fragment is merged into the host's
          ignition config at first boot, via `ignition.config.merge`
          in the instance metadata (cloud-init userdata, IPMI virtual
          media, or — in fleet tests — the per-machine
          `roles = [...]` shorthand in `lib/testing/fleet.nix`, which
          synthesises the same merge entry).
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

      # Kernel tunables this role needs. Rendered into the role's
      # ignitionConfig; applied at runtime only when the role's
      # ignition config is merged into the host's. Mirrors
      # `aos.kernel.{modules,sysctl}` from modules/base/kernel.nix —
      # same option names and types. Set unconditionally by role
      # files (NOT inside `lib.mkIf cfg.bundle`), exactly like
      # `systemd` above. `ignitionConfig` is computed for every
      # defined role so the fleet-spec enum and per-role assertions
      # can introspect it; only the bundle inclusion (and thus the
      # closure) is gated on `bundle`.
      kernel = {
        modules = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [];
        };
        sysctl = lib.mkOption {
          type = lib.types.attrsOf lib.types.str;
          default = {};
        };
      };

      # Firewall openings this role needs. Mirrors the additive subset
      # of `aos.firewall` (modules/security/firewall.nix) — same option
      # names and types. Host-global knobs (`enable`, `defaultPolicy`,
      # `trustedInterfaces`) are deliberately NOT mirrored: a role must
      # not be able to disable the firewall or flip the host's inbound
      # default policy.
      firewall = {
        allowedTCP = lib.mkOption {
          type = lib.types.listOf lib.types.port;
          default = [];
        };
        allowedUDP = lib.mkOption {
          type = lib.types.listOf lib.types.port;
          default = [];
        };
        forwardPolicy = lib.mkOption {
          type = lib.types.str;
          default = "drop";
        };
      };

      # Storage / files / users / kernelArguments that ignition should
      # write directly. Escape hatch for roles whose needs go beyond
      # systemd units (e.g. k3s wants /etc/rancher/k3s/config.yaml).
      ignitionExtras = lib.mkOption {
        type = ignitionFormat.type;
        default = {};
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

      # Computed: a derivation that diffs `render-role.nix`'s
      # predicted `storage.links` paths against the actual paths
      # produced by `generateUnits` for this role's typed
      # `systemd.*` inputs. Forced to evaluate via `ignitionRolesBundle`
      # so any toplevel referencing the role bundle catches drift
      # at build time. See spec v12 §5.6.2.
      driftCheck = lib.mkOption {
        type = lib.types.package;
        readOnly = true;
        internal = true;
        description = "Build-time drift check between predicted and actual storage.links paths.";
      };
    };

    config = let
      # Share the renderRole output across `ignitionConfig` and
      # `driftCheck` so we don't run the renderer (or its build-time
      # drift derivation) twice.
      renderedRole = renderRole {
        inherit name;
        inherit (config) systemd;
      };
    in {
      # Merge the role's typed systemd + kernel/firewall inputs with
      # `ignitionExtras` as a single definition. Shallow `//` rewrites
      # `storage.links` (which we extend with the role's predicted
      # unit-install symlinks); the other ignition top-level fields
      # (`passwd`, …) and the rest of `storage` (`files`,
      # `directories`) ride through extras unchanged.
      #
      # Spec v12 §5.6.4 removed `ignitionExtras.systemd` — roles now
      # express systemd units exclusively via the typed `systemd.*`
      # input, which `renderRole` projects into `storage.links` that
      # point at `unitsDrv` paths. There is no ignition-native systemd
      # surface anymore.
      ignitionConfig = let
        extras = config.ignitionExtras;
        extrasStorage =
          if (extras.storage or null) == null
          then {}
          else extras.storage;
        extrasLinks = extrasStorage.links or [];

        roleLinks = renderRoleLinks name config;
        unitLinks = renderedRole.storageLinks;
      in
        extras
        // lib.optionalAttrs (
          roleLinks != [] || unitLinks != [] || extrasStorage != {}
        ) {
          storage =
            extrasStorage
            // {
              links = extrasLinks ++ roleLinks ++ unitLinks;
            };
        };
      ignitionConfigDrv = ignitionFormat.generate name config.ignitionConfig;
      driftCheck = renderedRole.driftCheck;
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
  # the role doesn't override extras. Read defensively with `or null`.
  roleAssertions = name: role: let
    # The role's rendered kernel/firewall drop-in symlink paths must
    # not collide with any `path` in `ignitionExtras.storage.{files,
    # links}` — ignition would reject the duplicate at validate time,
    # but the eval-time check gives a better message.
    roleLinkPaths = builtins.map (l: l.path) (renderRoleLinks name role);
    extraStorage = role.ignitionExtras.storage or null;
    extraStoragePaths = lib.optionals (extraStorage != null) (
      builtins.map (f: f.path) extraStorage.files
      ++ builtins.map (l: l.path) extraStorage.links
    );
    linkCollisions =
      builtins.filter (p: builtins.elem p extraStoragePaths) roleLinkPaths;

    # Spec v12 §5.6.3 — the role's effective ignitionConfig is
    # bounded to /etc/-rooted storage entries and no
    # passwd/systemd/kernelArguments. Any deviation either silently
    # shadows declarative AOS state (passwd files via
    # modules/base/users.nix) or writes paths outside the per-gen
    # tmpfs that won't surface in the live overlay.
    ic = role.ignitionConfig;
    extraSystemd = role.ignitionExtras.systemd or null;
    badStoragePath = p: !(lib.hasPrefix "/etc/" p);
    nonEtcEntries = entries: pathField:
      builtins.filter (e: badStoragePath e.${pathField}) entries;
    icStorage =
      if (ic.storage or null) == null
      then {}
      else ic.storage;
    icLinks = icStorage.links or [];
    icFiles = icStorage.files or [];
    icDirs = icStorage.directories or [];
    nonEtcLinks = nonEtcEntries icLinks "path";
    nonEtcFiles = nonEtcEntries icFiles "path";
    nonEtcDirs = nonEtcEntries icDirs "path";
    nonEtcPaths =
      builtins.map (e: e.path) nonEtcLinks
      ++ builtins.map (e: e.path) nonEtcFiles
      ++ builtins.map (e: e.path) nonEtcDirs;
    kernelArgs = ic.kernelArguments or null;
    kernelArgsEmpty =
      kernelArgs
      == null
      || (
        (kernelArgs.shouldExist or [])
        == []
        && (kernelArgs.shouldNotExist or []) == []
      );
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
      assertion = linkCollisions == [];
      message = ''
        aos.roles."${name}": storage path collision between the
        role's rendered kernel/firewall drop-in links and
        ignitionExtras.storage.{files,links}:
        ${lib.concatStringsSep ", " linkCollisions}.
        Rename or remove one side to avoid a late
        ignition-validate duplicate-path failure.
      '';
    }
    {
      assertion = (ic.passwd or null) == null;
      message = ''
        aos.roles."${name}": role.ignitionConfig.passwd is not
        supported under the composefs /etc model (spec v12 §5.6.3).
        Ignition's files stage writes `$ign/etc/passwd` /
        `$ign/etc/shadow` / `$ign/etc/group`, which would silently
        shadow AOS's declarative passwd files
        (modules/base/users.nix:267). Future-work #6 lays out the
        deliberate-design path; the field is forbidden until then.
      '';
    }
    {
      assertion = extraSystemd == null;
      message = ''
        aos.roles."${name}": role.ignitionExtras.systemd is not
        supported under the composefs /etc model (spec v12 §5.6.4).
        The runtime preset-walker is removed; native ignition
        systemd units bypass the render-role drift assertion and the
        etc-merge-safety check. Use the typed `systemd.*` input on
        the role instead (its `wantedBy` / `overrideStrategy` etc.
        are projected through render-role.nix into the right
        storage.links).
      '';
    }
    {
      assertion = kernelArgsEmpty;
      message = ''
        aos.roles."${name}": role.ignitionConfig.kernelArguments
        writes to the bootloader, not the role lower. On stage-2
        re-runs (spec v12 §7) the change would be silently lost; on
        first boot, the typed `aos.kernel.*` options are the
        supported surface.
      '';
    }
    {
      assertion = nonEtcPaths == [];
      message = ''
        aos.roles."${name}": role.ignitionConfig.storage.* paths
        must start with `/etc/` (spec v12 §5.6.3). Anything outside
        `/etc/` writes to `$ign/<path>` inside the per-gen tmpfs,
        which is never mounted into the live system — silently
        lost. Offending paths:
        ${lib.concatStringsSep ", " nonEtcPaths}
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
    # `<role-name>` symlinks pointing at each bundled role's
    # pre-validated JSON. Stable filename per role (the role's name) →
    # operator-visible URL `file:///etc/aos/ignition-roles/<role-name>`
    # is rebuild-stable even though the bundle drv's hash isn't.
    #
    # Only roles with `bundle = true` are included: both the
    # `ln -sfn` loop and the `driftCheck` buildDeps list iterate over
    # the filtered set. Unbundled roles pay no closure cost — their
    # `ignitionConfigDrv` is never realised, and `renderRole`'s
    # unit-file derivations (which would drag in `ExecStart=` store
    # paths via Nix's text-reference scan) never enter the bundle's
    # closure.
    #
    # Empty-roles edge case: `lib.mapAttrsToList` over an empty
    # attrset produces `[]`, the `for`-equivalent loop emits no `ln`
    # lines, and the resulting derivation is an empty directory. Same
    # behaviour when nothing in `aos.roles.*` has `bundle = true` — a
    # host that bundles no roles still gets a working symlink target,
    # just one with nothing inside.
    #
    # Closure tracking note: Nix scans the bundle drv's `$out` for
    # `/nix/store/...` substrings to compute its references. The
    # symlinks we lay down contain those store paths as their target
    # text, so each bundled role's `ignitionConfigDrv` is pulled into
    # the bundle's closure transparently. The initrd-builder's
    # `exportReferencesGraph` addition then drags the whole closure
    # into the initrd's `/nix/store`. If this derivation ever changes
    # from "directory of symlinks" to something that doesn't embed
    # target paths as text (e.g. a tar archive), the closure-tracking
    # has to be re-established explicitly via `runtimeDeps` or similar.
    system.build.ignitionRolesBundle = let
      bundledRoles =
        lib.filterAttrs (_: role: role.bundle) config.aos.roles;
    in
      pkgs.mkDerivation {
        pname = "aos-ignition-roles-bundle";
        version = "0";
        src = null;
        # Every bundled role's `driftCheck` derivation is pulled in
        # as a build-time dep so the bundle (and thus the toplevel
        # and the initrd that ship it) refuse to build if predicted
        # storage.links don't match what `generateUnits` actually
        # lays down. See spec v12 §5.6.2. Unbundled roles skip drift
        # checking — the check would force their unit-file closure,
        # defeating the closure-size win of `bundle = false`. Drift
        # in an unbundled role surfaces the first time someone flips
        # `bundle = true` on it.
        buildDeps =
          [pkgs.coreutils]
          ++ lib.mapAttrsToList (_: role: role.driftCheck) bundledRoles;
        phases = [
          {
            name = "assemble";
            script = ''
              mkdir -p "$out"
              ${lib.concatStringsSep "\n" (
                lib.mapAttrsToList (
                  name: role: "ln -sfn ${role.ignitionConfigDrv}/${name} \"$out/${name}\""
                )
                bundledRoles
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
