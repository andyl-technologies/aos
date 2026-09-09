##! Qualifies public tier exports independently of their bootstrap build inputs.
{
  pkgs,
  buildPlatform,
}: let
  inventory = import ./toolchain-inventory.nix {inherit buildPlatform;};
  checkTier = name: packages:
    pkgs.mkDerivation {
      pname = "aos-toolchain-boundary-${name}";
      version = "1";
      src = null;
      buildDeps = [pkgs.python3];
      dontStrip = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            cat > inventory.json <<'INVENTORY'
            ${builtins.toJSON {${name} = packages;}}
            INVENTORY
            ${pkgs.python3}/bin/python3 ${./toolchain_boundaries.py} \
              inventory.json \
              report.json
            cp report.json "$out/report.json"
          '';
        }
      ];
    };
  checks = builtins.mapAttrs checkTier inventory;
  verifier = pkgs.mkDerivation {
    pname = "aos-toolchain-boundary-verifier";
    version = "1";
    src = null;
    buildDeps = [pkgs.python3];
    phases = [
      {
        name = "check";
        script = ''
          mkdir -p modules "$out"
          cp ${./toolchain_boundaries.py} modules/toolchain_boundaries.py
          cp ${./test_toolchain_boundaries.py} modules/test_toolchain_boundaries.py
          ${pkgs.python3}/bin/python3 -m unittest discover -s modules -v
          echo PASS > "$out/result"
        '';
      }
    ];
  };
in
  checks
  // {
    inherit verifier;
    all = pkgs.mkDerivation {
      pname = "aos-toolchain-boundaries";
      version = "1";
      src = null;
      buildDeps = [verifier] ++ builtins.attrValues checks;
      phases = [
        {
          name = "record";
          script = ''
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
    };
  }
