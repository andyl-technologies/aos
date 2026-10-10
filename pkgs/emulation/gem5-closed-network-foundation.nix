##! Native-owned finite TX/RX callbacks; no ordinary admission
{gem5-closed-block-foundation}: let
  patch = ./gem5-patches/closed-network-native-boundary.patch;
  witness = ./_gem5/closed-network-native-check.py;
  sourceRecord = builtins.toFile "closed-network-native-source.json" (builtins.toJSON {
    schema = "crucible.gem5.closed-network-native-source.v1";
    patchSha256 = builtins.hashFile "sha256" patch;
    witnessSha256 = builtins.hashFile "sha256" witness;
    recipeSha256 = builtins.hashFile "sha256" ./gem5-closed-network-foundation.nix;
    commonAdmissionQualified = false;
    opaqueCaptureQualified = false;
    cpuTimingQualified = false;
    fullDeviceParityQualified = false;
  });
in
  gem5-closed-block-foundation.overrideAttrs (previous: {
    pname = "gem5-closed-network-foundation";
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
          name = "closed-network-check";
          script = ''
            mkdir -p "$out/share/gem5/closed-network-source"
            for mode in enabled disabled; do
              build/ALL/gem5.opt --listener-mode=off --outdir="closed-network-$mode" \
                ${witness} "$mode" > "closed-network-$mode.log" 2>&1
              grep '"schema":"crucible.gem5.closed-network-native-boundary-mechanism.v1"' \
                "closed-network-$mode.log" > "$out/share/gem5/checks/closed-network-$mode.json"
            done
            cp ${sourceRecord} "$out/share/gem5/closed-network-source/manifest.json"
            cp ${patch} "$out/share/gem5/closed-network-source/closed-network-native-boundary.patch"
            cp ${witness} "$out/share/gem5/closed-network-source/closed-network-native-check.py"
            cp ${./gem5-closed-network-foundation.nix} "$out/share/gem5/closed-network-source/recipe.nix"
          '';
        }
      ];
    meta.description = "Native-owned TX birth, future RX and exact publication stops with original finite custody";
  })
