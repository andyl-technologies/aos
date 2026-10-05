# Test-only GPL-side native library for the original plugin callback unit.
{pkgs}: let
  fixture = ./block-wait-completion.c;
  interface = ./block-wait-completion.h;
  extractor = ./block-wait-completion-bodies.py;
  icountProvider = ./block-wait-icount-provider.c;
  nativeProfile = pkgs.callPackage ../../../pkgs/emulation/qemu.nix {
    pname = "qemu-crucible-block-wait-completion-unit";
    enablePlugins = true;
    applyCruciblePatch = true;
    enableLinuxUser = false;
    testOnlyNonDistributable = true;
  };
  selected = nativeProfile.passthru.atomicPatch;
in
  assert selected.commit == "39a0e603dd25905ada9f87276485375f9836b70c";
    nativeProfile.overrideAttrs (previous: {
      phases = let
        original = name:
          builtins.head (builtins.filter (phase: phase.name == name) previous.phases);
      in [
        (original "unpack")
        {
          name = "add-block-wait-completion-unit";
          script = ''
            cp ${fixture} tests/unit/block-wait-completion.c
            cp ${interface} tests/unit/block-wait-completion.h
            cp ${icountProvider} stubs/icount.c
            ${pkgs.python3}/bin/python3 ${extractor} . \
              tests/unit/block-wait-completion-bodies.inc
            cat >> tests/unit/meson.build <<'BLOCK_WAIT_UNIT'
            # The Rust libtest supplies the original registered callbacks.
            shared_module(
              'crucible-block-wait-completion-unit',
              'block-wait-completion.c', genh,
              '../../plugins/crucible-idle-wait.c',
              dependencies: [qemuutil, qom, migration, io],
              include_directories: include_directories('../..'),
              c_args: ['-ffunction-sections', '-fdata-sections', '-fvisibility=hidden'],
              link_args: ['-Wl,--gc-sections', '-Wl,--no-undefined'],
            )
            BLOCK_WAIT_UNIT
          '';
        }
        ((original "configure") // {
          # Only this loadable test adapter needs PIC unit libraries. The native
          # callback and timer bodies retain their ordinary configure guards.
          script = builtins.replaceStrings ["./configure \\"]
            ["./configure -Db_staticpic=true \\"]
            (original "configure").script;
        })
        {
          name = "build-block-wait-completion-unit";
          script = ''
            ${pkgs.ninja}/bin/ninja -C build -j$NIX_BUILD_CORES \
              tests/unit/libcrucible-block-wait-completion-unit.so
          '';
        }
        {
          name = "retain-block-wait-completion-unit";
          script = ''
            mkdir -p "$out/lib" "$out/share/aos/crucible"
            cp build/tests/unit/libcrucible-block-wait-completion-unit.so "$out/lib/"
            cp tests/unit/block-wait-completion-bodies.json \
              build/config-host.h build/compile_commands.json "$out/share/aos/crucible/"
            printf '%s\n' \
              'native_commit=${selected.commit}' \
              'native_tree=${selected.tree}' \
              'test_only_non_distributable=true' \
              'scope=actual-block-coroutine-and-timer-bodies-external-cpu-providers' \
              > "$out/share/aos/crucible/block-wait-completion-unit.env"
          '';
        }
      ];
    })
