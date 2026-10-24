##! Source-owned diagnostic Atomic graph; native capture/adoption remain refused
{gem5-closed-block-foundation}: let
  nativePatch = ./gem5-patches/native-original-scope-and-diagnostic-atomic-owners.patch;
  tableGeometryPatch = ./gem5-patches/native-selected-table-geometry.patch;
  lruBirthPatch = ./gem5-patches/native-lru-constructor-provenance.patch;
  walkerStatePatch = ./gem5-patches/native-arm-walker-source-state.patch;
  counterStatePatch = ./gem5-patches/native-system-counter-source-state.patch;
  counterCallablePatch = ./gem5-patches/native-system-counter-callable-owner.patch;
  nativeCheck = ./_gem5/native-original-scope-check.py;
  diagnosticGuest = ./_gem5/native-diagnostic-guest.py;
  record = builtins.toFile "gem5-native-original-scope-source.json" (builtins.toJSON {
    schema = "crucible.gem5.diagnostic-original-native-source.v1";
    recipeSha256 = builtins.hashFile "sha256" ./gem5-native-original-scope-foundation.nix;
    patchSha256 = builtins.hashFile "sha256" nativePatch;
    lruBirthPatchSha256 = builtins.hashFile "sha256" lruBirthPatch;
    walkerStatePatchSha256 = builtins.hashFile "sha256" walkerStatePatch;
    counterStatePatchSha256 = builtins.hashFile "sha256" counterStatePatch;
    counterObservationCheckSha256 = builtins.hashFile "sha256" ./_gem5/system-counter-observation-check.py;
    counterCallablePatchSha256 = builtins.hashFile "sha256" counterCallablePatch;
    diagnosticProfileVersion = 5;
    counterFrequencyCallable = "source-private-named-actual-owner-v1";
    completeCallbackClosureQualified = false;
    maximumCounterFrequencyEntries = 1004;
    maximumCounterFrequencyCapacityEntries = 2008;
    supportedCounterListeners = 0;
    fixedTableEntrySlots = 1280;
    tableGeometryPatchSha256 = builtins.hashFile "sha256" tableGeometryPatch;
    tableBankCheckSha256 = builtins.hashFile "sha256" ./_gem5/selected-table-banks-check.cc;
    tableMethodsWriterSha256 = builtins.hashFile "sha256" ./_gem5/selected-table-methods.py;
    fixedLruBirthSlots = 1472;
    lruBankCheckSha256 = builtins.hashFile "sha256" ./_gem5/lru-constructor-births-check.cc;
    lruFacadeWriterSha256 = builtins.hashFile "sha256" ./_gem5/replacement-data-facade.py;
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
    nativePatchFiles = previous.nativePatchFiles ++ [nativePatch lruBirthPatch tableGeometryPatch walkerStatePatch counterStatePatch counterCallablePatch];
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
                patch --fuzz=0 -p1 < ${lruBirthPatch}
                patch --fuzz=0 -p1 < ${tableGeometryPatch}
                patch --fuzz=0 -p1 < ${walkerStatePatch}
                patch --fuzz=0 -p1 < ${counterStatePatch}
                patch --fuzz=0 -p1 < ${counterCallablePatch}
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
            cp ${lruBirthPatch} "$out/share/gem5/native-original-scope-source/lru-births.patch"
            cp ${tableGeometryPatch} "$out/share/gem5/native-original-scope-source/table-geometry.patch"
            cp ${walkerStatePatch} "$out/share/gem5/native-original-scope-source/walker-state.patch"
            cp ${counterStatePatch} "$out/share/gem5/native-original-scope-source/counter-state.patch"
            cp ${counterCallablePatch} "$out/share/gem5/native-original-scope-source/counter-callable.patch"
            cp ${nativeCheck} "$out/share/gem5/native-original-scope-source/native-check.py"
            cp ${diagnosticGuest} "$out/share/gem5/native-original-scope-source/guest-source.py"
            cp ${./gem5-native-original-scope-foundation.nix} "$out/share/gem5/native-original-scope-source/recipe.nix"
          '';
        }
      ];
    meta.description = "Constructor-born native diagnostic Atomic ownership with exact private event/port/table members; native process, source-cut and restore admission remain refused";
  })
