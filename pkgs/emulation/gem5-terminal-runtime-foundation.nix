##! Isolated full original UART publication inventory; no runtime admission
{
  gem5-full-system-foundation,
  python3-3_12,
}: let
  inventoryPatch = ./gem5-patches/terminal-publication-inventory.patch;
  inventoryWitness = ./_gem5/terminal-publication-inventory-check.py;
  sourceRecord = builtins.toFile "terminal-runtime-source.json" (builtins.toJSON {
    schema = "crucible.gem5.terminal-runtime-source.v1";
    recipeSha256 = builtins.hashFile "sha256" ./gem5-terminal-runtime-foundation.nix;
    patchSha256 = builtins.hashFile "sha256" inventoryPatch;
    witnessSha256 = builtins.hashFile "sha256" inventoryWitness;
    fullSystemQualified = false;
  });
in
  gem5-full-system-foundation.overrideAttrs (previous: {
    pname = "gem5-terminal-runtime-foundation";
    phases =
      map (phase:
        if phase.name == "terminal-source"
        then
          phase
          // {
            script =
              phase.script
              + ''
                patch --fuzz=0 -p1 < ${inventoryPatch}
              '';
          }
        else phase)
      previous.phases
      ++ [
        {
          name = "terminal-inventory-check";
          script = ''
            build/ALL/gem5.opt --listener-mode=off --outdir=terminal-inventory-check \
              ${inventoryWitness} > terminal-inventory-check.log 2>&1
            grep '"all_same_callback_bytes_present":true' terminal-inventory-check.log
            mkdir -p "$out/share/gem5/terminal-runtime-source"
            grep '"schema":"crucible.gem5.terminal-publication-inventory-mechanism.v1"' \
              terminal-inventory-check.log > "$out/share/gem5/checks/terminal-publication-inventory.json"
            cp ${sourceRecord} "$out/share/gem5/terminal-runtime-source/manifest.json"
            cp ${inventoryPatch} "$out/share/gem5/terminal-runtime-source/terminal-publication-inventory.patch"
            cp ${inventoryWitness} "$out/share/gem5/terminal-runtime-source/terminal-publication-inventory-check.py"
            cp ${./gem5-terminal-runtime-foundation.nix} "$out/share/gem5/terminal-runtime-source/recipe.nix"
          '';
        }
      ];
    meta.description = "Observes all original serial publications from one callback without advancing or acknowledging the native FIFO; full-system admission remains refused";
  })
