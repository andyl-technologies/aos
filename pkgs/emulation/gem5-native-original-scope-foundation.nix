##! Source-owned diagnostic Atomic graph; native capture/adoption remain refused
{gem5-closed-block-foundation}: let
  nativePatch = ./gem5-patches/native-original-scope-and-diagnostic-atomic-owners.patch;
  nativeCheck = ./_gem5/native-original-scope-check.py;
  diagnosticGuest = ./_gem5/native-diagnostic-guest.py;
  record = builtins.toFile "gem5-native-original-scope-source.json" (builtins.toJSON {
    schema = "crucible.gem5.diagnostic-original-native-source.v1";
    recipeSha256 = builtins.hashFile "sha256" ./gem5-native-original-scope-foundation.nix;
    patchSha256 = builtins.hashFile "sha256" nativePatch;
    checkSha256 = builtins.hashFile "sha256" nativeCheck;
    guestSourceSha256 = builtins.hashFile "sha256" diagnosticGuest;
    diagnosticOnly = true;
    mandatoryDiagnosticCheckPackage = "gem5-native-original-scope-check";
    diagnosticCheckRecipeSha256 = builtins.hashFile "sha256" ./gem5-native-original-scope-check.nix;
    nativeProcessResourcesQualified = false;
    nativeSourceIssuerQualified = false;
    nativeEarlyAdopterQualified = false;
    opaqueCaptureQualified = false;
    commonNodeAdmissionQualified = false;
    generalIsaQualified = false;
    linuxQualified = false;
    fullDeviceParityQualified = false;
  });
in
  gem5-closed-block-foundation.overrideAttrs (previous: {
    pname = "gem5-native-original-scope-foundation";
    phases =
      map (phase:
        if phase.name == "terminal-source"
        then
          phase
          // {
            script =
              phase.script
              + ''
                patch --fuzz=0 -p1 < ${nativePatch}
              '';
          }
        else phase)
      previous.phases
      ++ [
        {
          name = "native-original-scope-source";
          script = ''
            # Native diagnostic controls are a mandatory separate check, so a
            # Python assertion cannot discard this full ALL compilation.
            mkdir -p "$out/share/gem5/native-original-scope-source"
            cp ${record} "$out/share/gem5/native-original-scope-source/manifest.json"
            cp ${nativePatch} "$out/share/gem5/native-original-scope-source/native.patch"
            cp ${nativeCheck} "$out/share/gem5/native-original-scope-source/native-check.py"
            cp ${diagnosticGuest} "$out/share/gem5/native-original-scope-source/guest-source.py"
            cp ${./gem5-native-original-scope-foundation.nix} "$out/share/gem5/native-original-scope-source/recipe.nix"
          '';
        }
      ];
    meta.description = "Constructor-born native diagnostic Atomic ownership with exact private event/port/table members; native process, source-cut and restore admission remain refused";
  })
