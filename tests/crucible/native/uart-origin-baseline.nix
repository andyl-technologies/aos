# GPL-side actual UART bodies with controlled external transport providers.
{pkgs}: let
  fixture = ./uart-origin-baseline.c;
  validator = ./uart-origin-baseline.py;
  unitName = "test-crucible-uart-origin-baseline";
  nativeProfile = pkgs.callPackage ../../../pkgs/emulation/qemu.nix {
    pname = "qemu-crucible-uart-origin-baseline";
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
        name = "add-uart-baseline-unit";
        script = ''
          cp ${fixture} tests/unit/${unitName}.c
          cat >> tests/unit/meson.build <<'UART_UNIT'
          # Test-only external providers; actual UART bodies and native libraries.
          uart_origin_baseline = executable(
            '${unitName}', '${unitName}.c',
            '../../hw/core/clock.c', '../../hw/core/clock-vmstate.c', genh,
            dependencies: [qemuutil, qom, migration, io],
            include_directories: include_directories('../..'),
            c_args: ['-ffunction-sections', '-fdata-sections'],
            link_args: ['-Wl,--gc-sections'],
          )
          test('${unitName}', uart_origin_baseline,
               env: test_env, args: ['--tap', '-k'], protocol: 'tap',
               suite: 'unit', timeout: 30)
          UART_UNIT
        '';
      }
      (original "configure")
      {
        name = "build-uart-baseline-unit";
        script = ''
          export PYTHONHASHSEED=0
          ${pkgs.python3}/bin/python3 ${validator} configured build
          ${pkgs.ninja}/bin/ninja -C build -j$NIX_BUILD_CORES tests/unit/${unitName}
        '';
      }
      {
        name = "execute-uart-baseline-unit";
        script = ''
          if ! build/pyvenv/bin/meson test -C build --no-rebuild \
            --num-processes 1 --print-errorlogs --logbase uart-origin \
            ${unitName} > uart-origin.result 2>&1; then
            cat uart-origin.result
            exit 1
          fi
          cat uart-origin.result
          ${pkgs.python3}/bin/python3 ${validator} executed \
            build/meson-logs/uart-origin.json build/compile_commands.json
        '';
      }
      {
        name = "retain-uart-baseline-evidence";
        script = ''
          # The test-only output retains evidence, never a linked unit/emulator.
          evidence="$out/share/aos/crucible"
          mkdir -p "$evidence"
          cp uart-origin.result "$evidence/"
          cp build/meson-logs/uart-origin.{json,txt} "$evidence/"
          cp uart-origin-compile.json "$evidence/"
          cp build/config-host.h "$evidence/"
          sha256sum hw/char/serial.c hw/char/pl011.c include/hw/char/serial.h \
            tests/unit/${unitName}.c > "$evidence/uart-source.sha256"
          cat > "$evidence/qemu-build-identity.env" <<'UART_IDENTITY'
          qemu_build_id=${unitProfile.passthru.qemuBuildIdentity}
          qemu_configure_flags_hash=${unitProfile.passthru.qemuConfigureFlagsHash}
          native_commit=${selected.commit}
          native_tree=${selected.tree}
          test_only_non_distributable=true
          qualification_scope=actual-uart-bodies-external-providers
          fixture_sha256=${builtins.hashFile "sha256" fixture}
          validator_sha256=${builtins.hashFile "sha256" validator}
          UART_IDENTITY
        '';
      }
    ];
  });
  sourcePackage = pkgs.callPackage ../../../pkgs/emulation/qemu-crucible-source.nix {
    qemu-crucible = unitProfile;
  };
in
  assert !pkgs.stdenv.isCross && pkgs.stdenv.hostPlatform.isLinux;
  assert selected.commit == "39a0e603dd25905ada9f87276485375f9836b70c";
    pkgs.mkDerivation {
      pname = "crucible-uart-origin-baseline";
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
              'scope=actual-uart-bodies-external-providers' \
              'native_origin_authority_qualified=false' > "$out/corresponding-source.env"
          '';
        }
      ];
    }
