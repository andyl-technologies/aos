##! gem5 functional Linux board variant with explicit absent FCH probe semantics
{
  gem5,
  python3-3_12,
}: let
  platformPatch = ./gem5-patches/x86-absent-fch-reset-status.patch;
  sourceExtension = builtins.toFile "gem5-linux-platform-source.json" (builtins.toJSON {
    recipeSha256 = builtins.hashFile "sha256" ./gem5-linux-platform.nix;
    manifestHelperSha256 = builtins.hashFile "sha256" ./_gem5/linux-platform-manifest.py;
    patches = [
      {
        file = "x86-absent-fch-reset-status.patch";
        sha256 = builtins.hashFile "sha256" platformPatch;
      }
    ];
    fullSystemQualified = false;
  });
in
  gem5.overrideAttrs (previous: {
    pname = "gem5-linux-platform";
    phases =
      [
        (builtins.head previous.phases)
        {
          name = "platform-source";
          script = ''
            patch --fuzz=0 -p1 < ${platformPatch}
          '';
        }
      ]
      ++ builtins.tail previous.phases
      ++ [
        {
          name = "platform-check";
          script = ''
            build/ALL/gem5.opt --listener-mode=off --outdir=absent-register-check \
              ${./_gem5/x86-absent-fch-check.py} > absent-register-check.log 2>&1
            grep '"nativeCases":10' absent-register-check.log
            mkdir -p "$out/share/gem5/checks"
            grep '"schema":"crucible.gem5.absent-fch-reset-status-mechanism.v1"' \
              absent-register-check.log > "$out/share/gem5/checks/absent-fch-reset-status.json"
          '';
        }
        {
          name = "platform-manifest";
          script = ''
            ${python3-3_12}/bin/python3 ${./_gem5/linux-platform-manifest.py} \
              "$out/share/gem5/source-manifest.json" ${sourceExtension}
            mkdir -p "$out/share/gem5/platform-source"
            cp ${platformPatch} "$out/share/gem5/platform-source/x86-absent-fch-reset-status.patch"
            cp ${./gem5-linux-platform.nix} "$out/share/gem5/platform-source/recipe.nix"
            cp ${./_gem5/linux-platform-manifest.py} "$out/share/gem5/platform-source/manifest-helper.py"
          '';
        }
      ];
    meta.description = "Functional Linux board variant with a bounded explicit error response for an absent optional FCH reset-status register; no exact admission";
  })
