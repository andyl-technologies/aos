# Reuses the real package's unpack/configure phases for bounded native checks.
{pkgs}: {
  attrPath,
  pname,
  gateName,
  description,
  runner,
  identityFileName,
  boundPhaseName,
  runPhaseName,
  runnerArguments ? "",
  compiler ? null,
  testTimeoutSeconds ? 60,
}: let
  buildTimeoutSeconds = 600;
  addressSpaceBytes = 6 * 1024 * 1024 * 1024;

  focusedBuilder = package: let
    configurePhases =
      builtins.filter
      (phase: builtins.elem phase.name ["unpack" "configure"])
      package.phases;
    identity = builtins.toFile identityFileName ''
      ${package.passthru.qemuBuildIdentityMaterial}
      qemu_build_id=${package.passthru.qemuBuildIdentity}
    '';
  in
    assert builtins.map (phase: phase.name) configurePhases == ["unpack" "configure"];
      pkgs.mkDerivation (
        builtins.removeAttrs package ["qualification" "checks" "module" "moduleDeps"]
        // {
          inherit pname;
          outputs = ["out"];
          buildDeps =
            package.buildDeps
            ++ [pkgs.coreutils]
            ++ (
              if compiler == null
              then []
              else [compiler]
            );
          dontStrip = "1";
          dontNukeRefs = "1";
          phases =
            [
              {
                name = boundPhaseName;
                script =
                  ''
                    # Applies to the genuine unpack/configure/compiler children too.
                    ulimit -v ${toString (addressSpaceBytes / 1024)}
                    export PYTHONDONTWRITEBYTECODE=1
                  ''
                  + (
                    if compiler == null
                    then ""
                    else ''
                      # Select the complete matching compiler/runtime before the
                      # unpack ABI probe and QEMU's genuine configure checks.
                      export PATH=${compiler}/bin:$PATH
                      export CC=${compiler}/bin/cc
                      export CXX=${compiler}/bin/c++
                    ''
                  );
              }
            ]
            ++ configurePhases
            ++ [
              {
                name = runPhaseName;
                script = ''
                  set -eu
                  export PYTHONHASHSEED=0
                  ${pkgs.python3}/bin/python3 ${runner} \
                    --source-root "$PWD" \
                    --ninja ${pkgs.ninja}/bin/ninja \
                    --identity ${identity} \
                    --abi-header ${package.passthru.shmemGeneratedHeader} \
                    --build-timeout ${toString buildTimeoutSeconds} \
                    --test-timeout ${toString testTimeoutSeconds} \
                    --address-space-bytes ${toString addressSpaceBytes} \
                    --output "$out" ${runnerArguments}
                '';
              }
            ];
          passthru = {
            inherit attrPath buildTimeoutSeconds testTimeoutSeconds addressSpaceBytes;
            inherit (package.passthru) qemuBuildIdentity atomicPatchHash shmemHeaderHash;
            inherit gateName;
            testOnlyNonDistributable = true;
            standaloneRelease = false;
          };
          meta =
            package.meta
            // {
              inherit description;
              # Scheduler hint for this check, separate from dependency builds.
              timeout = 1200;
            };
        }
      );
in
  assert !pkgs.stdenv.isCross;
  assert pkgs.stdenv.hostPlatform.isLinux;
  assert pkgs.stdenv.hostPlatform.constraints.cpu == "x86_64";
    pkgs.callPackage ../../pkgs/emulation/qemu.nix {
      mkDerivation = focusedBuilder;
      pname = "qemu-crucible";
      enablePlugins = true;
      applyCruciblePatch = true;
      testOnlyNonDistributable = true;
    }
