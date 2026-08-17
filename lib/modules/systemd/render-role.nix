##! lib/modules/systemd/render-role.nix — role systemd → pure plan + materialized units.
##!
##! Per spec v12 §5.6. The helper takes a role's typed `systemd.*`
##! inputs and returns `{ unitsDrv, storageLinks, driftCheck }`:
##!
##!   - `unitsDrv` materializes the pure `generateUnits` output. The role's
##!     config lower binds this into `/run/etc/config-<gen>/etc/`
##!     via the per-link entries below; at runtime the overlay merges
##!     it with the system EROFS image's `/systemd/system/` tree.
##!
##!   - `storageLinks` is the eval-time prediction of paths
##!     `generateUnits` will lay down under `unitsDrv`. The prediction
##!     is mechanical from typed inputs; the drift assertion catches
##!     any divergence at build time.
##!
##!   - `driftCheck` is a `runCommand` derivation that diffs the
##!     prediction against `unitsDrv`'s actual content. Wire it into
##!     the role's eval product so any toplevel referencing the role
##!     forces the assertion to pass.
##!
##! Role units do not depend on a runtime preset walker. Instead, the helper
##! predicts every path
##! `generateUnits` lays down (top-level unit files, `.wants` /
##! `.requires` / `.upholds` install symlinks, aliases) and emits one
##! `storage.links` entry per path. The configuration materializer then
##! realizes each prediction inside the per-generation lower's
##! `/etc/systemd/system/...` subtree.
{
  lib,
  pkgs,
  systemdLib,
}: let
  inherit (systemdLib) generateUnits materializeUnits unitsToEtc;

  # Normalise a role's typed `systemd.*` attrsets into the
  # `generateUnits`-shaped attrset. Mirrors `modules/systemd/
  # system.nix:47-65`'s `renderedUnits`.
  withName = renderer: def: lib.nameValuePair (renderer def).name (renderer def);

  renderUnits = systemd:
    lib.mapAttrs' (_: withName systemdLib.serviceToUnit) systemd.services
    // lib.mapAttrs' (_: withName systemdLib.targetToUnit) systemd.targets
    // lib.mapAttrs' (_: withName systemdLib.socketToUnit) systemd.sockets
    // lib.mapAttrs' (_: withName systemdLib.timerToUnit) systemd.timers
    // lib.mapAttrs' (_: withName systemdLib.pathToUnit) systemd.paths
    // lib.mapAttrs' (_: withName systemdLib.sliceToUnit) systemd.slices
    // lib.listToAttrs (
      builtins.map (withName systemdLib.mountToUnit) systemd.mounts
    )
    // lib.listToAttrs (
      builtins.map (withName systemdLib.automountToUnit) systemd.automounts
    );

  # Build the prediction table from spec v12 §5.6.1. Every entry's
  # `path` is the in-/etc location the role configuration materializer will
  # symlink; `target` is the corresponding path inside `unitsDrv`.
  #
  # `asDropin` semantics per the §5.6.1 table: suppress only the
  # top-level unit-file row; the `.wants` / `.requires` / `.upholds` /
  # aliases rows are still emitted. Matches
  # `lib/modules/systemd/lib.nix:613-625` (asDropin emits only the
  # drop-in) plus `:638-671` (install-symlink loops iterate ALL
  # units, including asDropin).
  predictLinks = unitsDrv: units: let
    mkLink = path: target: {
      inherit path target;
      overwrite = true;
    };

    perUnitLinks = name: unit: let
      etcBase = "/etc/systemd/system";
      drvBase = "${unitsDrv}";

      # Top-level unit file (asDropin suppresses).
      topLevel = lib.optional (unit.overrideStrategy or "asDropinIfExists" != "asDropin") (
        mkLink "${etcBase}/${unit.name}" "${drvBase}/${unit.name}"
      );

      # asDropin drop-in file (only for asDropin).
      asDropin = lib.optional ((unit.overrideStrategy or "") == "asDropin") (
        mkLink "${etcBase}/${unit.name}.d/overrides.conf"
        "${drvBase}/${unit.name}.d/overrides.conf"
      );

      installSyms = field:
        lib.concatMap (
          target: [
            (mkLink
              "${etcBase}/${target}.${field}/${unit.name}"
              "${drvBase}/${target}.${field}/${unit.name}")
          ]
        );

      wantsLinks = installSyms "wants" (unit.wantedBy or []);
      requiresLinks = installSyms "requires" (unit.requiredBy or []);
      upholdsLinks = installSyms "upholds" (unit.upheldBy or []);

      aliasLinks = builtins.map (
        alias: mkLink "${etcBase}/${alias}" "${drvBase}/${alias}"
      ) (unit.aliases or []);
    in
      topLevel ++ asDropin ++ wantsLinks ++ requiresLinks ++ upholdsLinks ++ aliasLinks;
  in
    lib.concatLists (lib.mapAttrsToList perUnitLinks units);

  # Build-time drift assertion (spec §5.6.2): the actual file set in
  # `unitsDrv` must exactly match the prediction. Catches divergence
  # between this file and `generateUnits` (e.g. a future asDropin
  # rule change, a new install-link field, an alias bug).
  mkDriftCheck = roleName: unitsDrv: storageLinks: let
    expectedPaths =
      builtins.map (
        l: lib.removePrefix "/etc/systemd/system/" l.path
      )
      storageLinks;
    expectedText = lib.concatStringsSep "\n" (lib.unique (lib.sort builtins.lessThan expectedPaths));
  in
    pkgs.runCommand "render-role-drift-${roleName}" {
      expected = expectedText;
      passAsFile = ["expected"];
      inherit unitsDrv;
    } ''
      set -eu
      ( cd "$unitsDrv" && find . -mindepth 1 \( -type f -o -type l \) ) \
        | sed 's|^\./||' | sort -u > actual.txt
      sort -u "$expectedPath" > expected.txt
      if ! diff -u expected.txt actual.txt; then
        echo
        echo "render-role drift for role ${roleName}:"
        echo "  expected and actual paths under unitsDrv differ; see diff above."
        exit 1
      fi
      touch "$out"
    '';
in
  {
    name,
    systemd,
  }: let
    renderedUnits = renderUnits systemd;
    pureUnits = generateUnits {
      type = "system";
      units = renderedUnits;
      upstreamUnits = [];
      upstreamWants = [];
      packages = [];
    };
    jobScripts = lib.listToAttrs (builtins.map (job:
      lib.nameValuePair job.key {
        text = job.body;
        inherit (job) mode;
        name = job.scriptName;
      })
    (lib.concatLists (lib.mapAttrsToList (_: service: service.jobScripts) systemd.services)));
    unitsDrv = materializeUnits {
      type = "system";
      etc = unitsToEtc pureUnits;
      inherit jobScripts;
    };
    storageLinks = predictLinks unitsDrv renderedUnits;
    driftCheck = mkDriftCheck name unitsDrv storageLinks;
  in {
    inherit unitsDrv storageLinks driftCheck;
  }
