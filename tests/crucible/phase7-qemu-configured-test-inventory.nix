{pkgs}: let
  suite = pkgs.qemu-crucible-full-test-suite;
  configurePhases =
    builtins.filter
    (phase: builtins.elem phase.name ["unpack" "configure"])
    suite.passthru.phases;
in
  assert builtins.map (phase: phase.name) configurePhases == ["unpack" "configure"];
  assert suite.passthru.qemuBuildIdentity == pkgs.qemu-crucible.passthru.qemuBuildIdentity;
    suite.overrideAttrs (previous: {
      pname = "crucible-qemu-configured-test-inventory";
      # Configuration uses the complete thorough-suite inputs and flags, but
      # executes no emulator or test. KVM is required by the separate full run.
      requiredSystemFeatures = [];
      exportReferencesGraph = [];
      dontStrip = "1";
      dontNukeRefs = "1";
      phases =
        configurePhases
        ++ [
          {
            name = "record-configured-test-inventory";
            script = ''
              set -eu
              mkdir -p "$out"
              ${pkgs.python3}/bin/python3 ${./qemu-test-inventory-tests.py} \
                ${./qemu-test-inventory.py}
              test -s build/meson-info/intro-tests.json
              (
                cd build
                ./pyvenv/bin/meson test --no-rebuild --setup thorough --list
              ) > "$out/thorough.inventory"
              test -s "$out/thorough.inventory"
              cp build/meson-info/intro-tests.json "$out/intro-tests.json"
              cp build/meson-info/intro-buildoptions.json "$out/intro-buildoptions.json"
              ${pkgs.python3}/bin/python3 ${./qemu-test-inventory.py} configured \
                ${./qemu-thorough-test-inventory.txt} "$out/thorough.inventory" \
                --introspection "$out/intro-tests.json" > "$out/coverage"
              cat > "$out/result" <<RESULT
              PASS
              gate=gate:qemu-configured-test-inventory
              qemu_build_id=${suite.passthru.qemuBuildIdentity}
              atomic_patch_commit=${suite.passthru.atomicPatch.commit}
              test_execution=none
              RESULT
              cat "$out/coverage" >> "$out/result"
            '';
          }
        ];
      passthru =
        previous.passthru
        // {
          attrPath = "checks.crucible.phase7.qemuConfiguredTestInventory";
          gateName = "gate:qemu-configured-test-inventory";
        };
    })
