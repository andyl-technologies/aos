# Build an actual alternate source revision with the ordinary Worker recipe.
# The changed comment affects source identity without changing the wire ABI.
{
  lib,
  pkgs,
  worker,
  selected ? null,
}: let
  variantSource = pkgs.runCommand "hub-fleet-alternate-worker-source" {} ''
    cp -R ${worker.src}/. "$out"
    chmod u+w "$out/crates/aos-hub-worker/src/lib.rs"
    printf '\n%s\n' '// This source snapshot belongs to the fleet revision-refusal fixture.' \
      >> "$out/crates/aos-hub-worker/src/lib.rs"
  '';
  originalDigest = builtins.hashString "sha256" (toString worker.src);
  variantDigest = builtins.hashString "sha256" (toString variantSource);
  defaultDistribution = worker.overrideAttrs (previous: {
    src = variantSource;
    phases = map (phase:
      if phase.name == "build-wasm"
      then assert builtins.length (lib.splitString originalDigest phase.script) == 2;
        phase
        // {
          script = builtins.replaceStrings [originalDigest] [variantDigest] phase.script;
        }
      else phase)
    previous.phases;
  });
  selection =
    if selected == null
    then {
      source = variantSource;
      distribution = defaultDistribution;
      purpose = "comment-only-source-revision";
    }
    else selected;
in
  assert builtins.length (builtins.filter (phase: phase.name == "build-wasm") worker.passthru.phases) == 1;
  assert builtins.attrNames selection == ["distribution" "purpose" "source"];
  assert builtins.elem selection.purpose ["comment-only-source-revision" "retained-source-revision"];
  assert toString selection.source != toString worker.src;
  assert toString selection.distribution != toString worker; {
    inherit (selection) source distribution purpose;
    sourceDigest = builtins.hashString "sha256" (toString selection.source);
    scriptVersion = "emulated-${builtins.hashString "sha256" (toString selection.source)}";
    features = ["do-e2e"];
    scope = "alternate revision for a refusal only; never current qualification";
  }
