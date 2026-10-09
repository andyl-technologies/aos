##! Source-owned fixed ARM Linux process-image and UART continuation mechanism
{
  mkDerivation,
  gem5-terminal-runtime-foundation,
  gem5-aarch64-linux,
  gem5-aarch64-linux-device-fixture,
  gem5-aarch64-bootloader,
  dmtcp,
  gem5-process-custody,
  python3,
  coreutils,
  abseil-cpp,
}: let
  helperNames = [
    "native-controller.py"
    "native-controller-models.py"
    "native-controller-arm.py"
    "native-controller-arm-model.py"
    "native-controller-arm-check.py"
    "native-controller-image-check.py"
    "native-controller-image-custody-check.py"
    "native-model-assets.py"
    "native-model-assets-check.py"
    "process-image-audit-core.py"
    "full-system-process-image-audit.py"
    "full-system-process-image-audit-check.py"
  ];
  helperSource = builtins.path {
    path = ./_gem5;
    name = "gem5-arm-controller-proof-source";
    filter = path: type: type == "directory" && builtins.baseNameOf path == "_gem5" || builtins.elem (builtins.baseNameOf path) helperNames;
  };
  sourceManifest = builtins.toFile "gem5-arm-controller-proof-source.json" (builtins.toJSON {
    schema = "crucible.gem5.arm-controller-proof-source.v1";
    recipe_sha256 = builtins.hashFile "sha256" ./gem5-shared-controller-arm-check.nix;
    helpers = builtins.listToAttrs (map (name: {
        inherit name;
        value = builtins.hashFile "sha256" (./_gem5 + "/${name}");
      })
      helperNames);
    execution_admission_qualified = false;
    full_system_admission_qualified = false;
  });
in
  mkDerivation {
    pname = "gem5-shared-controller-arm-check";
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
    buildDeps = [python3 coreutils];
    runtimeDeps = [
      gem5-terminal-runtime-foundation
      gem5-aarch64-linux
      gem5-aarch64-linux-device-fixture
      gem5-aarch64-bootloader
      dmtcp
      gem5-process-custody
    ];
    phases = [
      {
        name = "check";
        script = ''
          export PYTHONDONTWRITEBYTECODE=1
          ${python3}/bin/python3 -B ${helperSource}/native-model-assets-check.py \
            ${helperSource}/native-model-assets.py
          ${python3}/bin/python3 -B ${helperSource}/full-system-process-image-audit-check.py
          ${python3}/bin/python3 -B ${helperSource}/native-controller-image-custody-check.py
          export LD_LIBRARY_PATH="${abseil-cpp}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          witness_root="$(mktemp -d /tmp/gem5-arm-shared-controller.XXXXXXXX)"
          ${coreutils}/bin/timeout 600 ${python3}/bin/python3 -B \
            ${helperSource}/native-controller-arm-check.py \
            ${gem5-terminal-runtime-foundation}/bin/gem5 ${helperSource} "$witness_root/native" \
            ${gem5-terminal-runtime-foundation}/share/gem5/configs \
            ${gem5-aarch64-linux}/boot/vmlinux \
            ${gem5-aarch64-linux-device-fixture}/initrd.img \
            ${gem5-aarch64-bootloader}/share/gem5/bootloader/boot_v2.arm64 \
            ${dmtcp} ${gem5-process-custody}/lib/libcrucible-resource-custody.so > native-check.log
          cp "$witness_root/native/result.json" summary.json
          rm -rf "$witness_root"
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/checks" "$out/share/gem5/arm-controller-proof-source" \
            "$out/share/licenses/gem5-shared-controller-arm-check"
          cp summary.json "$out/share/checks/arm-linux-shared-controller.json"
          cp ${sourceManifest} "$out/share/gem5/arm-controller-proof-source/manifest.json"
          cp ${helperSource}/*.py "$out/share/gem5/arm-controller-proof-source/"
          cp ${./gem5-shared-controller-arm-check.nix} "$out/share/gem5/arm-controller-proof-source/recipe.nix"
          cp ${../../LICENSES/MIT.txt} "$out/share/licenses/gem5-shared-controller-arm-check/LICENSE"
        '';
      }
    ];
    meta = {
      description = "Audits a fixed ARM Linux process image and original held UART receipt after complete source namespace deletion and two fresh recaptures; grants no production execution, timing, readiness, or device capability";
      license = "MIT";
    };
  }
