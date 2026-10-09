##! Isolated native terminal-publication foundation; no full-system admission
{
  gem5-linux-platform,
  python3-3_12,
}: let
  outputPatch = ./gem5-patches/terminal-output-publication.patch;
  witnessPatch = ./gem5-patches/terminal-output-native-witness.patch;
  sourceExtension = builtins.toFile "gem5-full-system-source.json" (builtins.toJSON {
    recipeSha256 = builtins.hashFile "sha256" ./gem5-full-system-foundation.nix;
    manifestHelperSha256 = builtins.hashFile "sha256" ./_gem5/terminal-source-manifest.py;
    patches = [
      {
        file = "terminal-output-publication.patch";
        sha256 = builtins.hashFile "sha256" outputPatch;
      }
      {
        file = "terminal-output-native-witness.patch";
        sha256 = builtins.hashFile "sha256" witnessPatch;
      }
    ];
    fullSystemQualified = false;
  });
in
  gem5-linux-platform.overrideAttrs (previous: {
    pname = "gem5-full-system-foundation";
    phases =
      [
        (builtins.head previous.phases)
        {
          name = "terminal-source";
          script = ''
            patch --fuzz=0 -p1 < ${outputPatch}
            patch --fuzz=0 -p1 < ${witnessPatch}
          '';
        }
      ]
      ++ builtins.tail previous.phases
      ++ [
        {
          name = "terminal-check";
          script = ''
            build/ALL/gem5.opt --listener-mode=off --outdir=terminal-check \
              ${./_gem5/terminal-output-check.py} > terminal-check.log 2>&1
            grep '"actualCallbackBirth":true' terminal-check.log
            grep '"schema":"crucible.gem5.terminal-publication-mechanism.v1"' \
              terminal-check.log > "$out/share/gem5/checks/terminal-publication.json"
          '';
        }
        {
          name = "terminal-source-manifest";
          script = ''
            ${python3-3_12}/bin/python3 ${./_gem5/terminal-source-manifest.py} \
              "$out/share/gem5/source-manifest.json" ${sourceExtension}
            mkdir -p "$out/share/gem5/terminal-source"
            cp ${outputPatch} "$out/share/gem5/terminal-source/terminal-output-publication.patch"
            cp ${witnessPatch} "$out/share/gem5/terminal-source/terminal-output-native-witness.patch"
            cp ${./gem5-full-system-foundation.nix} "$out/share/gem5/terminal-source/recipe.nix"
            cp ${./_gem5/terminal-source-manifest.py} "$out/share/gem5/terminal-source/manifest-helper.py"
          '';
        }
      ];
    meta.description = "Preserves native serial publication identity and FIFO custody; full-system exact qualification remains refused";
  })
