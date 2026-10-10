##! Explicit bounded native device diagnostic scope; no profile admission
{
  gem5-terminal-runtime-foundation,
  python3-3_12,
}: let
  observerPatch = ./gem5-patches/causal-device-inventory.patch;
  fifoPatch = ./gem5-patches/device-original-fifo-inventory.patch;
  witness = ./_gem5/causal-device-inventory-check.py;
  record = builtins.toFile "causal-device-source.json" (builtins.toJSON {
    schema = "crucible.gem5.causal-device-source.v1";
    recipeSha256 = builtins.hashFile "sha256" ./gem5-causal-device-foundation.nix;
    observerPatchSha256 = builtins.hashFile "sha256" observerPatch;
    fifoPatchSha256 = builtins.hashFile "sha256" fifoPatch;
    witnessSha256 = builtins.hashFile "sha256" witness;
    includedDiagnosticScope = "native-events-rng-selected-device-fields-v1";
    omittedDiagnosticDomains = [
      "unselected-simobject-modeled-fields"
      "cpu-pipeline-and-registers"
      "cache-tags-data-and-transients"
      "memory-controller-and-dram"
      "complete-owner-and-delivery-custody"
      "unknown-polymorphic-event-and-device-payloads"
    ];
    typedDiagnosticComplete = false;
    opaqueCaptureQualified = false;
    commonNodeAdmissionQualified = false;
    fullDeviceParityQualified = false;
  });
in
  gem5-terminal-runtime-foundation.overrideAttrs (previous: {
    pname = "gem5-causal-device-foundation";
    phases =
      map (phase:
        if phase.name == "terminal-source"
        then
          phase
          // {
            script =
              phase.script
              + ''
                patch --fuzz=0 -p1 < ${observerPatch}
                patch --fuzz=0 -p1 < ${fifoPatch}
              '';
          }
        else phase)
      previous.phases
      ++ [
        {
          name = "causal-device-check";
          script = ''
            build/ALL/gem5.opt --listener-mode=off --outdir=causal-device-check \
              ${witness} > causal-device-check.log 2>&1
            grep '"schema":"crucible.gem5.causal-device-diagnostic-mechanism.v1"' \
              causal-device-check.log > "$out/share/gem5/checks/causal-device.json"
            mkdir -p "$out/share/gem5/causal-device-source"
            cp ${record} "$out/share/gem5/causal-device-source/manifest.json"
            cp ${observerPatch} "$out/share/gem5/causal-device-source/causal-device-inventory.patch"
            cp ${fifoPatch} "$out/share/gem5/causal-device-source/device-original-fifo-inventory.patch"
            cp ${witness} "$out/share/gem5/causal-device-source/causal-device-inventory-check.py"
            cp ${./gem5-causal-device-foundation.nix} "$out/share/gem5/causal-device-source/recipe.nix"
          '';
        }
      ];
    meta.description = "Observes selected original device queues and native causal state without promoting partial typed coverage or modifying existing profiles";
  })
