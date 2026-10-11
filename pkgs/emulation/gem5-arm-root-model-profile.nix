##! Source-owned ARM Linux model mechanism bundle; grants no public admission
{
  mkDerivation,
  gem5-shared-controller-arm-root-check,
  gem5-terminal-runtime-foundation,
  gem5-aarch64-linux,
  gem5-aarch64-linux-device-fixture,
  gem5-aarch64-bootloader,
  dmtcp,
  gem5-process-custody,
  python3,
}: let
  proof = gem5-shared-controller-arm-root-check;
  source = "${proof}/share/gem5/arm-controller-proof-source";
  native = gem5-terminal-runtime-foundation;
  specification = builtins.toJSON {
    configuration_tree = "${native}/share/gem5/configs";
    artifacts = {
      native_executable = "${native}/bin/gem5";
      native_source_manifest = "${native}/share/gem5/source-manifest.json";
      terminal_runtime_manifest = "${native}/share/gem5/terminal-runtime-source/manifest.json";
      terminal_inventory_patch = "${native}/share/gem5/terminal-runtime-source/terminal-publication-inventory.patch";
      terminal_runtime_recipe = "${native}/share/gem5/terminal-runtime-source/recipe.nix";
      terminal_inventory_witness = "${native}/share/gem5/terminal-runtime-source/terminal-publication-inventory-check.py";
      controller = "${source}/native-controller.py";
      entrypoint = "${source}/native-controller-arm-root.py";
      model = "${source}/native-controller-arm-root-model.py";
      board_model = "${source}/native-controller-arm-model.py";
      model_check = "${source}/native-controller-arm-root-model-check.py";
      publication_model = "${source}/native-controller-models.py";
      asset_checker = "${source}/native-model-assets.py";
      asset_check = "${source}/native-model-assets-check.py";
      auditor = "${source}/full-system-process-image-audit.py";
      auditor_core = "${source}/process-image-audit-core.py";
      auditor_check = "${source}/full-system-process-image-audit-check.py";
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
      witness = "${source}/native-controller-arm-root-check.py";
      image_witness = "${source}/native-controller-image-check.py";
      image_custody_check = "${source}/native-controller-image-custody-check.py";
      mechanism_evidence = "${proof}/share/checks/arm-linux-shared-controller.json";
      profile_writer = "@out@/share/gem5/arm-profile-source/manifest.py";
      profile_recipe = "@out@/share/gem5/arm-profile-source/recipe.nix";
    };
  };
in
  mkDerivation {
    pname = "gem5-arm-root-model-profile";
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
    # Every executable, fixed guest artifact and source-owned actual mechanism
    # witness remains retained. The bundle is not a production catalog entry.
    runtimeDeps = [
      proof
      native
      gem5-aarch64-linux
      gem5-aarch64-linux-device-fixture
      gem5-aarch64-bootloader
      dmtcp
      gem5-process-custody
      python3
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/share/crucible/gem5" "$out/share/gem5/arm-profile-source" \
            "$out/share/licenses/gem5-arm-root-model-profile"
          cp ${./_gem5/arm-root-model-profile-manifest.py} "$out/share/gem5/arm-profile-source/manifest.py"
          cp ${./_gem5/arm-root-model-profile-manifest-check.py} "$out/share/gem5/arm-profile-source/check.py"
          cp ${./gem5-arm-root-model-profile.nix} "$out/share/gem5/arm-profile-source/recipe.nix"
          cp ${../../LICENSES/MIT.txt} "$out/share/licenses/gem5-arm-root-model-profile/LICENSE"
          chmod 444 "$out/share/gem5/arm-profile-source/"*
          cat > profile-inputs.json <<'EOF'
          ${specification}
          EOF
          ${python3}/bin/python3 -B -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text(p.read_text().replace("@out@",sys.argv[2]))' \
            profile-inputs.json "$out"
          ${python3}/bin/python3 -B "$out/share/gem5/arm-profile-source/manifest.py" \
            profile-inputs.json "$out/share/crucible/gem5/arm-model-profile.json"
        '';
      }
      {
        name = "check";
        script = ''
          ${python3}/bin/python3 -B "$out/share/gem5/arm-profile-source/check.py" \
            "$out/share/gem5/arm-profile-source/manifest.py" \
            "${proof}/share/checks/arm-linux-shared-controller.json" \
            "$out/share/crucible/gem5/arm-model-profile.json"
        '';
      }
    ];
    meta = {
      description = "Binds immutable native/controller/assets and actual source-gone twin capture mechanism evidence for one fixed ARM Linux model without granting execution, device, readiness, or timing admission";
      license = "MIT";
    };
  }
