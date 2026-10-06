# Actual GPL-side shutdown bodies; external services never choose exit status.
{pkgs}: let
  fixture = ./plugin-failed-exit.c;
  validator = ./plugin-failed-exit-bodies.py;
  extractor = ./block-wait-completion-bodies.py;
  unitName = "test-crucible-plugin-failed-exit";
  nativeProfile = pkgs.callPackage ../../../pkgs/emulation/qemu.nix {
    pname = "qemu-crucible-plugin-failed-exit";
    enablePlugins = true;
    applyCruciblePatch = true;
    enableLinuxUser = false;
    testOnlyNonDistributable = true;
  };
  selected = nativeProfile.passthru.atomicPatch;
  unitProfile = nativeProfile.overrideAttrs (previous: {
    phases = let
      original = name:
        builtins.head (builtins.filter (phase: phase.name == name) previous.phases);
    in [
      (original "unpack")
      {
        name = "add-plugin-failed-exit-unit";
        script = ''
          cp ${fixture} tests/unit/${unitName}.c
          ${pkgs.python3}/bin/python3 ${validator} extract . \
            tests/unit/plugin-failed-exit-bodies.inc ${extractor}
          cat >> tests/unit/meson.build <<'SHUTDOWN_UNIT'
          plugin_failed_exit = executable(
            '${unitName}', '${unitName}.c', genh,
            dependencies: [qemuutil],
            include_directories: include_directories('../..'),
          )
          test('${unitName}', plugin_failed_exit,
               env: test_env, args: ['--tap', '-k'], protocol: 'tap',
               suite: 'unit', timeout: 30)
          SHUTDOWN_UNIT
        '';
      }
      (original "configure")
      {
        name = "build-plugin-failed-exit-unit";
        script = ''
          ${pkgs.python3}/bin/python3 ${validator} configured build
          ${pkgs.ninja}/bin/ninja -C build -j$NIX_BUILD_CORES tests/unit/${unitName}
        '';
      }
      {
        name = "execute-plugin-failed-exit-unit";
        script = ''
          if ! build/pyvenv/bin/meson test -C build --no-rebuild \
            --num-processes 1 --print-errorlogs --logbase plugin-failed-exit \
            ${unitName} > plugin-failed-exit.result 2>&1; then
              cat plugin-failed-exit.result
              exit 1
          fi
          cat plugin-failed-exit.result
          ${pkgs.python3}/bin/python3 ${validator} executed build
        '';
      }
      {
        name = "retain-plugin-failed-exit-evidence";
        script = ''
          evidence="$out/share/aos/crucible"
          mkdir -p "$evidence"
          cp plugin-failed-exit.result plugin-failed-exit-compile.json "$evidence/"
          cp build/meson-logs/plugin-failed-exit.{json,txt} "$evidence/"
          cp tests/unit/plugin-failed-exit-bodies.{inc,json} "$evidence/"
          cp build/config-host.h "$evidence/"
          sha256sum plugins/api-system.c system/runstate.c \
            tests/unit/${unitName}.c > "$evidence/plugin-failed-exit-source.sha256"
          cat > "$evidence/qemu-build-identity.env" <<'SHUTDOWN_IDENTITY'
          qemu_build_id=${unitProfile.passthru.qemuBuildIdentity}
          qemu_configure_flags_hash=${unitProfile.passthru.qemuConfigureFlagsHash}
          native_commit=${selected.commit}
          native_tree=${selected.tree}
          test_only_non_distributable=true
          scope=actual-shutdown-bodies-external-services-real-subprocess-status
          SHUTDOWN_IDENTITY
        '';
      }
    ];
  });
  sourcePackage = pkgs.callPackage ../../../pkgs/emulation/qemu-crucible-source.nix {
    qemu-crucible = unitProfile;
  };
in
  assert !pkgs.stdenv.isCross && pkgs.stdenv.hostPlatform.isLinux;
    pkgs.mkDerivation {
      pname = "crucible-plugin-failed-exit";
      version = "0";
      src = null;
      buildDeps = [pkgs.coreutils pkgs.grep unitProfile];
      runtimeDeps = [sourcePackage];
      phases = [
        {
          name = "retain-corresponding-source";
          script = ''
            source_root=${sourcePackage}/share/aos/qemu-crucible-source
            grep -Fxq 'qemu_build_id=${unitProfile.passthru.qemuBuildIdentity}' \
              "$source_root/SOURCE-MANIFEST.env"
            grep -Fxq 'qemu_configure_flags_hash=${unitProfile.passthru.qemuConfigureFlagsHash}' \
              "$source_root/SOURCE-MANIFEST.env"
            mkdir -p "$out"
            cp -R ${unitProfile}/share/aos/crucible/. "$out/"
            printf '%s\n' 'corresponding_source=${sourcePackage}' \
              'scope=actual-shutdown-bodies-external-services-real-subprocess-status' \
              'physical_vm_qualified=false' > "$out/corresponding-source.env"
          '';
        }
      ];
    }
