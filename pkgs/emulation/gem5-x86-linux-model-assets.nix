##! Fixed source-built x86 Linux assets and private launch-data preparation
{
  mkDerivation,
  gem5-native-original-scope-foundation,
  gem5-x86-model-components,
  gem5-x86-linux-loader-check,
  gem5-x86-linux-device-fixture,
  linux,
  python3,
}: let
  native = gem5-native-original-scope-foundation;
  components = "${gem5-x86-model-components}/share/gem5/x86-model-components";
  fixture = gem5-x86-linux-device-fixture;
  kernelVersion = builtins.replaceStrings ["="] [""] linux.version;
  specification = builtins.toJSON {
    configuration_root = "${native}/share/gem5/configs";
    artifacts = {
      native_executable = "${native}/bin/gem5";
      native_source_manifest = "${native}/share/gem5/source-manifest.json";
      controller = "${components}/native-controller.py";
      entrypoint = "${components}/native-controller-x86.py";
      model = "${components}/native-controller-x86-model.py";
      publication_model = "${components}/native-controller-models.py";
      asset_checker = "${components}/native-model-assets.py";
      loader = "${components}/x86-linux-loader.py";
      component_manifest = "${components}/manifest.json";
      loader_check = "${gem5-x86-linux-loader-check}/share/checks/x86-linux-loader.json";
      kernel = "${linux.vmlinux}/boot/vmlinux-${kernelVersion}";
      kernel_configuration = "${linux}/boot/config-${kernelVersion}";
      pid1 = "${fixture}/init";
      initramfs = "${fixture}/initrd.img";
      pid1_checker = "${fixture.source}/linux-init-artifact-check.py";
    };
  };
in
  mkDerivation {
    pname = "gem5-x86-linux-model-assets";
    version = "1";
    inherit specification;
    passAsFile = ["specification"];
    outputs = ["out" "source"];
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
    # The immutable bundle keeps the full native corresponding source and guest
    # producers. It does not declare a native boot/capture/admission witness.
    runtimeDeps = [
      native
      native.source
      gem5-x86-model-components
      gem5-x86-linux-loader-check
      fixture
      fixture.source
      linux
      linux.vmlinux
      python3
    ];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/crucible/gem5" \
            "$out/share/licenses/gem5-x86-linux-model-assets" "$source"
          cp ${./_gem5/x86-linux-bundle.py} "$source/x86-linux-bundle.py"
          cp ${./_gem5/x86-linux-bundle-check.py} "$source/x86-linux-bundle-check.py"
          cp ${./gem5-x86-linux-model-assets.nix} "$source/recipe.nix"
          cp ${../kernel/linux.nix} "$source/kernel-recipe.nix"
          cp "$specificationPath" "$source/selected-artifacts.json"
          ln -s ${linux.src} "$source/kernel-source-archive"
          cp ${../../LICENSES/MIT.txt} "$source/LICENSE"
          cp ${../../LICENSES/MIT.txt} "$out/share/licenses/gem5-x86-linux-model-assets/LICENSE"
          ln -s "$source" "$out/share/corresponding-source"
          ${python3}/bin/python3 -I -B "$source/x86-linux-bundle.py" build \
            "$specificationPath" "$out/share/crucible/gem5/x86-linux-assets.json"
          cat > "$out/bin/gem5-x86-prepare" <<EOF
          #!${python3}/bin/python3.14
          import os, sys
          os.execv("${python3}/bin/python3.14", ["${python3}/bin/python3.14", "-I", "-B", "$source/x86-linux-bundle.py", "prepare", "$out/share/crucible/gem5/x86-linux-assets.json", *sys.argv[1:]])
          EOF
          chmod 555 "$out/bin/gem5-x86-prepare"
        '';
      }
      {
        name = "check";
        script = ''
          ${python3}/bin/python3 -I -B "$source/x86-linux-bundle.py" inspect \
            "$out/share/crucible/gem5/x86-linux-assets.json"
          ${python3}/bin/python3 -I -B "$source/x86-linux-bundle-check.py" \
            "$source/x86-linux-bundle.py" "$specificationPath" \
            "$PWD/x86-model-asset-check" > "$source/x86-model-asset-check.json"
        '';
      }
    ];
    meta = {
      description = "Binds actual fixed x86 Linux/PID1/configuration assets and prepares private controller data without emulator execution or native capture/readiness qualification";
      license = "MIT";
    };
  }
