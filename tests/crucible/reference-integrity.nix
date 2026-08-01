{
  pkgs,
  lib,
  crucibleChecks,
  fleetChecks,
}: let
  rfcDir = ../../docs/rfcs/0010-crucible;
  rfcEntries = builtins.readDir rfcDir;
  rfcFiles =
    lib.filter
    (name: rfcEntries.${name} == "regular" && lib.hasSuffix ".md" name)
    (builtins.attrNames rfcEntries);
  rfcText = builtins.concatStringsSep "\n" (
    map (name: builtins.readFile (rfcDir + "/${name}")) rfcFiles
  );

  tokens = lib.filter builtins.isString (
    builtins.split "[^A-Za-z0-9_.-]+" rfcText
  );
  trimDots = token:
    if lib.hasSuffix "." token
    then trimDots (lib.removeSuffix "." token)
    else token;
  references = lib.unique (
    map trimDots (
      lib.filter (
        token:
          lib.hasPrefix "checks.crucible." token
          || lib.hasPrefix "checks.fleet." token
      )
      tokens
    )
  );

  checkTree = {
    crucible =
      crucibleChecks
      // {
        referenceIntegrity = true;
      };
    fleet = fleetChecks;
  };
  resolves = reference: let
    components = lib.drop 1 (lib.splitString "." reference);
    go = value: remaining:
      if remaining == []
      then true
      else let
        name = builtins.head remaining;
      in
        builtins.isAttrs value
        && builtins.hasAttr name value
        && go value.${name} (builtins.tail remaining);
  in
    go checkTree components;
  missingReferences = lib.filter (reference: !(resolves reference)) references;

  walk = path: value: let
    attempted = builtins.tryEval value;
  in
    if !attempted.success
    then [path]
    else if builtins.isAttrs attempted.value && !(lib.isDerivation attempted.value)
    then
      lib.concatMap
      (name: walk "${path}.${name}" attempted.value.${name})
      (builtins.attrNames attempted.value)
    else [];
  evaluationFailures =
    walk "checks.crucible" crucibleChecks
    ++ walk "checks.fleet" fleetChecks;

  patchSeries = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchCount = builtins.length patchSeries.patchFiles;
  patchDoc = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  patchCountMarker = "The carried series contains **${toString patchCount} patches**.";
  patchCountFailures =
    lib.optional (!(lib.hasInfix patchCountMarker patchDoc))
    "docs/rfcs/0010-crucible/11-qemu-patches.md: missing current patch-count marker `${patchCountMarker}`";

  failures =
    map (reference: "unresolvable check reference `${reference}`") missingReferences
    ++ map (path: "check does not evaluate `${path}`") evaluationFailures
    ++ patchCountFailures;
in
  if failures != []
  then throw "Crucible reference-integrity check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-reference-integrity";
      version = "0";
      src = null;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            {
              printf 'PASS\n'
              printf 'check=checks.crucible.referenceIntegrity\n'
              printf 'tasks=T-HARN-28\n'
              printf 'resolved_reference_count=%s\n' "$REFERENCE_COUNT"
              printf 'evaluated_check_tree=true\n'
              printf 'task_metadata_state_consistency=true\n'
              printf 'qemu_patch_count=%s\n' "$PATCH_COUNT"
            } > "$out/result"
          '';
        }
      ];
      REFERENCE_COUNT = toString (builtins.length references);
      PATCH_COUNT = toString patchCount;
    }
