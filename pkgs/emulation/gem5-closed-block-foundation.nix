##! Native-owned closed block callbacks; no ordinary admission
{gem5-causal-device-foundation}: let
  patch = ./gem5-patches/closed-block-native-boundary.patch;
  witness = ./_gem5/closed-block-native-check.py;
  sourceRecord = builtins.toFile "closed-block-native-source.json" (builtins.toJSON {
    schema = "crucible.gem5.closed-block-native-source.v1";
    patchSha256 = builtins.hashFile "sha256" patch;
    witnessSha256 = builtins.hashFile "sha256" witness;
    recipeSha256 = builtins.hashFile "sha256" ./gem5-closed-block-foundation.nix;
    commonAdmissionQualified = false;
    opaqueCaptureQualified = false;
    cpuTimingQualified = false;
    fullDeviceParityQualified = false;
  });
in
  gem5-causal-device-foundation.overrideAttrs (previous: {
    pname = "gem5-closed-block-foundation";
    phases =
      map (phase:
        if phase.name == "terminal-source"
        then
          phase
          // {
            script =
              phase.script
              + ''
                patch --fuzz=0 -p1 < ${patch}
              '';
          }
        else phase)
      previous.phases
      ++ [
        {
          name = "closed-block-check";
          script = ''
            mkdir -p "$out/share/gem5/closed-block-source"
            for mode in enabled disabled; do
              build/ALL/gem5.opt --listener-mode=off --outdir="closed-block-$mode" \
                ${witness} "$mode" > "closed-block-$mode.log" 2>&1
              grep '"schema":"crucible.gem5.closed-block-native-boundary-mechanism.v1"' \
                "closed-block-$mode.log" > "$out/share/gem5/checks/closed-block-$mode.json"
            done
            cp ${sourceRecord} "$out/share/gem5/closed-block-source/manifest.json"
            cp ${patch} "$out/share/gem5/closed-block-source/closed-block-native-boundary.patch"
            cp ${witness} "$out/share/gem5/closed-block-source/closed-block-native-check.py"
            cp ${./gem5-closed-block-foundation.nix} "$out/share/gem5/closed-block-source/recipe.nix"
          '';
        }
      ];
    meta.description = "Native-owned request callbacks and exact publication stops with separately typed completion status";
  })
