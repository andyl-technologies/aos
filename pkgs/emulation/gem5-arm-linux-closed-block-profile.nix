##! Source-bound fixed device/image mechanism bundle; no ordinary catalog grant
{
  mkDerivation,
  gem5-arm-linux-block-lifecycle-check,
  gem5-closed-block-foundation,
  gem5-aarch64-linux,
  gem5-aarch64-linux-device-fixture,
  gem5-aarch64-bootloader,
  gem5-process-custody,
  dmtcp,
  python3,
}: let
  proof = gem5-arm-linux-block-lifecycle-check;
  native = gem5-closed-block-foundation;
  source = "${proof}/share/gem5/arm-device-proof-source";
  specification = builtins.toJSON {
    configuration_tree = "${native}/share/gem5/configs";
    artifacts = {
      native_executable = "${native}/bin/gem5";
      native_diagnostic_manifest = "${native}/share/gem5/causal-device-source/manifest.json";
      native_diagnostic_patch = "${native}/share/gem5/causal-device-source/causal-device-inventory.patch";
      native_fifo_patch = "${native}/share/gem5/causal-device-source/device-original-fifo-inventory.patch";
      controller = "${source}/native-controller-device.py";
      entrypoint = "${source}/native-controller-arm-block.py";
      model = "${source}/native-controller-arm-block-model.py";
      device_model = "${source}/native-controller-arm-devices-model.py";
      owned_backend = "${source}/closed-memory-block.py";
      native_boundary_manifest = "${native}/share/gem5/closed-block-source/manifest.json";
      native_boundary_patch = "${native}/share/gem5/closed-block-source/closed-block-native-boundary.patch";
      native_boundary_witness = "${native}/share/gem5/closed-block-source/closed-block-native-check.py";
      native_boundary_recipe = "${native}/share/gem5/closed-block-source/recipe.nix";
      board_model = "${source}/native-controller-arm-model.py";
      publication_model = "${source}/native-controller-models.py";
      asset_checker = "${source}/native-model-assets.py";
      auditor = "${source}/closed-block-process-image-audit.py";
      auditor_core = "${source}/process-image-audit-core.py";
      image_guard = "${gem5-process-custody}/lib/libcrucible-resource-custody.so";
      dmtcp_launch = "${dmtcp}/bin/dmtcp_launch";
      dmtcp_restart = "${dmtcp}/bin/dmtcp_restart";
      mtcp_restart = "${dmtcp}/bin/mtcp_restart";
      python = "${python3}/bin/python3.14";
      kernel = "${gem5-aarch64-linux}/boot/vmlinux";
      initramfs = "${gem5-aarch64-linux-device-fixture}/initrd.img";
      firmware = "${gem5-aarch64-bootloader}/share/gem5/bootloader/boot_v2.arm64";
      source_manifest = "${source}/manifest.json";
      source_recipe = "${source}/recipe.nix";
      witness = "${source}/native-controller-arm-block-check.py";
      image_witness = "${source}/closed-block-image-check.py";
      archive_custody = "${source}/device-archive-custody.py";
      diagnostic_projection = "${source}/causal-device-projection.py";
      mechanism_evidence = "${proof}/share/checks/arm-linux-block-lifecycle.json";
      profile_writer = "@out@/share/gem5/device-profile-source/closed-block-profile.py";
      license_inventory = "@out@/share/gem5/device-profile-source/LICENSES.md";
    };
  };
in
  mkDerivation {
    pname = "gem5-arm-linux-closed-block-profile";
    version = "1";
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    buildDeps = [python3];
    runtimeDeps = [
      proof
      native
      gem5-aarch64-linux
      gem5-aarch64-linux-device-fixture
      gem5-aarch64-bootloader
      gem5-process-custody
      dmtcp
      python3
    ];
    phases = [
      {
        name = "check";
        script = ''
          mkdir profile-source
          cp ${./_gem5/closed-block-profile.py} profile-source/closed-block-profile.py
          cp ${./_gem5/closed-block-profile-check.py} profile-source/closed-block-profile-check.py
          ${python3}/bin/python3 -B profile-source/closed-block-profile-check.py
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/crucible/gem5" "$out/share/gem5/device-profile-source"
          cp profile-source/*.py "$out/share/gem5/device-profile-source/"
          cp ${./gem5-patches/LICENSES.md} "$out/share/gem5/device-profile-source/LICENSES.md"
          cp ${./gem5-arm-linux-closed-block-profile.nix} "$out/share/gem5/device-profile-source/recipe.nix"
          cat > profile-specification.json <<'EOF'
          ${specification}
          EOF
          ${python3}/bin/python3 -B - "$out" <<'PY'
          import json
          from pathlib import Path
          import sys
          path = Path('profile-specification.json')
          body = path.read_text().replace('@out@', sys.argv[1])
          path.write_text(body)
          PY
          ${python3}/bin/python3 -B ${./_gem5/closed-block-profile.py} profile-specification.json \
            ${proof}/share/checks/arm-linux-block-lifecycle.json \
            "$out/share/crucible/gem5/closed-block-profile.json"
        '';
      }
    ];
    meta = {
      description = "Binds actual closed Linux application disk lifecycle, owned native events and source-gone twin image mechanism evidence; no common Ready or device timing grant";
      license = "MIT";
    };
  }
