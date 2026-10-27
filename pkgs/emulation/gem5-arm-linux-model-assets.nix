##! Fixed source-built ARM Linux assets and private VExpress launch data
{
  mkDerivation,
  gem5-native-original-scope-foundation,
  gem5-aarch64-linux,
  gem5-aarch64-linux-device-fixture,
  gem5-aarch64-bootloader,
  python3,
}: let
  native = gem5-native-original-scope-foundation;
  kernel = gem5-aarch64-linux;
  fixture = gem5-aarch64-linux-device-fixture;
  firmware = gem5-aarch64-bootloader;
  helperNames = [
    "native-controller.py"
    "native-controller-arm.py"
    "native-controller-arm-model.py"
    "native-controller-models.py"
    "native-model-assets.py"
    "linux-model-data.py"
    "arm-linux-loader.py"
    "arm-linux-bundle.py"
    "arm-linux-boot-data-check.py"
  ];
  helpers = builtins.path {
    path = ./_gem5;
    name = "gem5-arm-linux-assets";
    filter = path: type:
      type == "directory" && builtins.baseNameOf path == "_gem5"
      || builtins.elem (builtins.baseNameOf path) helperNames;
  };
  specification = builtins.toJSON {
    configuration_root = "${native}/share/gem5/configs";
    helper_hashes = builtins.listToAttrs (map (name: {
      inherit name;
      value = builtins.hashFile "sha256" (./_gem5 + "/${name}");
    }) [
      "native-controller.py"
      "native-controller-arm.py"
      "native-controller-arm-model.py"
      "native-controller-models.py"
      "native-model-assets.py"
      "arm-linux-loader.py"
    ]);
    artifacts = {
      native_executable = "${native}/bin/gem5";
      native_source_manifest = "${native}/share/gem5/source-manifest.json";
      controller = "${helpers}/native-controller.py";
      entrypoint = "${helpers}/native-controller-arm.py";
      model = "${helpers}/native-controller-arm-model.py";
      publication_model = "${helpers}/native-controller-models.py";
      asset_checker = "${helpers}/native-model-assets.py";
      loader = "${helpers}/arm-linux-loader.py";
      kernel = "${kernel}/boot/vmlinux";
      kernel_configuration = "${kernel.source}/build/config";
      firmware = "${firmware}/share/gem5/bootloader/boot_v2.arm64";
      firmware_source = "${firmware}/share/gem5/bootloader/source/boot.S";
      firmware_makefile = "${firmware}/share/gem5/bootloader/source/makefile";
      pid1 = "${fixture}/init";
      initramfs = "${fixture}/initrd.img";
      pid1_checker = "${fixture.source}/linux-init-artifact-check.py";
    };
  };
in
  mkDerivation {
    pname = "gem5-arm-linux-model-assets";
    version = "1";
    outputs = ["out" "source"];
    inherit specification;
    passAsFile = ["specification"];
    platformSupport = {
      build = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    buildDeps = [python3];
    runtimeDeps = [native native.source kernel kernel.source fixture fixture.source firmware python3];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/crucible/gem5" "$source"
          cp ${helpers}/*.py "$source/"
          cp ${./gem5-arm-linux-model-assets.nix} "$source/recipe.nix"
          cp "$specificationPath" "$source/selected-artifacts.json"
          cp ${../../LICENSES/MIT.txt} "$source/LICENSE"
          ln -s ${native.source} "$source/native-corresponding-source"
          ln -s ${kernel.source} "$source/kernel-corresponding-source"
          ln -s ${fixture.source} "$source/pid1-corresponding-source"
          ln -s ${firmware}/share/gem5/bootloader/source "$source/firmware-corresponding-source"
          ln -s "$source" "$out/share/corresponding-source"
          ${python3}/bin/python3 -I -B "$source/arm-linux-bundle.py" build \
            "$specificationPath" "$out/share/crucible/gem5/arm-linux-assets.json"
          cat > "$out/bin/gem5-arm-prepare" <<EOF
          #!${python3}/bin/python3.14
          import os, sys
          os.execv("${python3}/bin/python3.14", ["${python3}/bin/python3.14", "-I", "-B", "$source/arm-linux-bundle.py", "prepare", "$out/share/crucible/gem5/arm-linux-assets.json", *sys.argv[1:]])
          EOF
          chmod 555 "$out/bin/gem5-arm-prepare"
        '';
      }
      {
        name = "check";
        script = ''
          ${python3}/bin/python3 -I -B "$source/arm-linux-bundle.py" inspect \
            "$out/share/crucible/gem5/arm-linux-assets.json"
          ${python3}/bin/python3 -I -B "$source/arm-linux-boot-data-check.py" \
            "$source" "$specificationPath" > "$source/arm-linux-data-check.json"
        '';
      }
    ];
    meta = {
      description = "Binds actual ARM kernel, firmware, PID1 and VExpress configuration data without native boot, capture or common-node authority";
      license = "MIT";
    };
  }
