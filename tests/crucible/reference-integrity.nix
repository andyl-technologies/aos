{
  pkgs,
  lib,
  crucibleChecks,
  fleetChecks,
}: let
  # Every check attribute path named by the Crucible engineering pages must
  # resolve in the check tree, so documentation cannot cite removed checks.
  engineeringDocDir = ../../docs/engineering/crucible;
  engineeringDocEntries = builtins.readDir engineeringDocDir;
  engineeringDocFiles =
    lib.filter
    (name: engineeringDocEntries.${name} == "regular" && lib.hasSuffix ".md" name)
    (builtins.attrNames engineeringDocEntries);
  engineeringDocText = builtins.concatStringsSep "\n" (
    map (name: builtins.readFile (engineeringDocDir + "/${name}")) engineeringDocFiles
  );

  tokens = lib.filter builtins.isString (
    builtins.split "[^A-Za-z0-9_.-]+" engineeringDocText
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
    go = value: remaining: let
      attempted = builtins.tryEval value;
    in
      if !attempted.success
      # Evaluation failures are reported by `walk`; they must not abort or be
      # misclassified as unresolved documentation references here.
      then true
      else if remaining == []
      then true
      else let
        name = builtins.head remaining;
      in
        builtins.isAttrs attempted.value
        && builtins.hasAttr name attempted.value
        && go attempted.value.${name} (builtins.tail remaining);
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

  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  patchDoc = builtins.readFile ../../docs/engineering/crucible/qemu-patch.md;
  atomicPatchMarker = "The shipped integration contains **one atomic final-state patch**";
  patchContractFailures =
    lib.optional (!(builtins.pathExists (../../pkgs/emulation/qemu-patches + "/${atomicPatch.file}")))
    "pkgs/emulation/qemu-patches/_atomic-patch.nix: atomic patch artifact is absent"
    ++ lib.optional (!(lib.hasInfix atomicPatchMarker patchDoc))
    "docs/engineering/crucible/qemu-patch.md: missing current atomic-patch marker `${atomicPatchMarker}`";

  failures =
    map (reference: "unresolvable check reference `${reference}`") missingReferences
    ++ map (path: "check does not evaluate `${path}`") evaluationFailures
    ++ patchContractFailures;
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
              printf 'resolved_reference_count=%s\n' "$REFERENCE_COUNT"
              printf 'evaluated_check_tree=true\n'
              printf 'qemu_atomic_patch=%s\n' "$ATOMIC_PATCH"
              printf 'qemu_atomic_patch_hash=%s\n' "$ATOMIC_PATCH_HASH"
            } > "$out/result"
          '';
        }
      ];
      REFERENCE_COUNT = toString (builtins.length references);
      ATOMIC_PATCH = atomicPatch.file;
      ATOMIC_PATCH_HASH = atomicPatch.sha256;
    }
