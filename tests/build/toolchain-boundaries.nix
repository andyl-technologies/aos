##! Qualifies public tier exports independently of their bootstrap build inputs.
{
  pkgs,
  buildPlatform,
  hostPlatform ? buildPlatform,
  # The build host's binfmt mapping must resolve to this AOS-built executable.
  # The verifier checks the guest shell separately from its emulator process.
  emulator ?
    if hostPlatform.constraints.cpu == buildPlatform.constraints.cpu
    then null
    else "${pkgs.qemu}/bin/qemu-${hostPlatform.constraints.cpu}",
}: let
  inventory = import ./toolchain-inventory.nix {inherit buildPlatform hostPlatform;};
  targetSuffix =
    if hostPlatform.system == buildPlatform.system
    then ""
    else "-${hostPlatform.system}";
  checkTier = name: packages:
    pkgs.mkDerivation {
      pname = "aos-toolchain-boundary-${name}${targetSuffix}";
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
            mkdir -p modules
            cp ${./toolchain_boundaries.py} modules/toolchain_boundaries.py
            cp ${./toolchain_elf.py} modules/toolchain_elf.py
            ${pkgs.python3}/bin/python3 modules/toolchain_boundaries.py \
              inventory.json \
              report.json --syscall-source ${./toolchain-syscalls.c} \
              --readelf ${pkgs.binutils}/bin/readelf \
              --cxx-source ${./toolchain-cxx.cc} ${
              if emulator == null
              then ""
              else "--emulator ${emulator}"
            }
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
          cp ${./toolchain_elf.py} modules/toolchain_elf.py
          cp ${./test_toolchain_elf.py} modules/test_toolchain_elf.py
          cp ${./test_toolchain_boundaries.py} modules/test_toolchain_boundaries.py
          cp ${../../stdenv/runtime_python_scripts.py} modules/runtime_python_scripts.py
          cp ${./test_runtime_python_scripts.py} modules/test_runtime_python_scripts.py
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
    runtime-scripts = import ./runtime-scripts.nix {inherit pkgs;};
    cc-wrapper-binutils = import ./cc-wrapper-binutils.nix {inherit pkgs;};
    all = pkgs.mkDerivation {
      pname = "aos-toolchain-boundaries${targetSuffix}";
      version = "1";
      src = null;
      buildDeps =
        [
          verifier
          (import ./runtime-scripts.nix {inherit pkgs;})
          (import ./cc-wrapper-binutils.nix {inherit pkgs;})
        ]
        ++ builtins.attrValues checks;
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
