##! Closed ARM Linux device/image foundation; no ordinary-node admission
{
  mkDerivation,
  gem5-closed-network-foundation,
  gem5-aarch64-linux,
  gem5-aarch64-linux-device-fixture,
  gem5-aarch64-bootloader,
  dmtcp,
  gem5-process-custody,
  python3,
  coreutils,
  abseil-cpp,
}: let
  native = gem5-closed-network-foundation;
  helpers = {
    "native-controller-device.py" = ./_gem5/native-controller-device.py;
    "native-controller-models.py" = ./_gem5/native-controller-models.py;
    "native-controller-arm-model.py" = ./_gem5/native-controller-arm-model.py;
    "native-controller-arm-devices.py" = ./_gem5/native-controller-arm-devices.py;
    "native-controller-arm-devices-model.py" = ./_gem5/native-controller-arm-devices-model.py;
    "native-controller-arm-devices-model-check.py" = ./_gem5/native-controller-arm-devices-model-check.py;
    "native-controller-arm-network-check.py" = ./_gem5/native-controller-arm-network-check.py;
    "native-model-assets.py" = ./_gem5/native-model-assets.py;
    "causal-device-projection.py" = ./_gem5/causal-device-projection.py;
    "causal-device-projection-check.py" = ./_gem5/causal-device-projection-check.py;
    "device-image-check.py" = ./_gem5/device-image-check.py;
    "device-archive-custody.py" = ./_gem5/device-archive-custody.py;
    "device-archive-custody-check.py" = ./_gem5/device-archive-custody-check.py;
    "causal-device-process-image-audit.py" = ./_gem5/causal-device-process-image-audit.py;
    "closed-memory-block.py" = ./_gem5/closed-memory-block.py;
    "closed-memory-block-check.py" = ./_gem5/closed-memory-block-check.py;
    "native-controller-arm-block.py" = ./_gem5/native-controller-arm-block.py;
    "native-controller-arm-block-model.py" = ./_gem5/native-controller-arm-block-model.py;
    "native-controller-arm-block-model-check.py" = ./_gem5/native-controller-arm-block-model-check.py;
    "native-controller-arm-network-model.py" = ./_gem5/native-controller-arm-network-model.py;
    "native-controller-arm-network-model-check.py" = ./_gem5/native-controller-arm-network-model-check.py;
    "native-controller-arm-network-board.py" = ./_gem5/native-controller-arm-network-board.py;
    "native-controller-arm-network.py" = ./_gem5/native-controller-arm-network.py;
    "closed-network-loopback.py" = ./_gem5/closed-network-loopback.py;
    "closed-network-loopback-check.py" = ./_gem5/closed-network-loopback-check.py;
    "closed-network-image-check.py" = ./_gem5/closed-network-image-check.py;
    "closed-network-process-image-audit.py" = ./_gem5/closed-network-process-image-audit.py;
    "process-image-audit-core.py" = ./_gem5/process-image-audit-core.py;
  };
  names = builtins.attrNames helpers;
  copyHelpers = builtins.concatStringsSep "\n" (map
    (name: "cp ${helpers.${name}} helper-source/${name}")
    names);
  record = builtins.toFile "gem5-arm-device-proof-source.json" (builtins.toJSON {
    schema = "crucible.gem5.arm-device-proof-source.v1";
    recipe_sha256 = builtins.hashFile "sha256" ./gem5-arm-linux-network-lifecycle-check.nix;
    helpers = builtins.listToAttrs (map (name: {
        inherit name;
        value = builtins.hashFile "sha256" helpers.${name};
      })
      names);
    controller_patch_sha256 = builtins.hashFile "sha256" ./gem5-patches/native-controller-device.patch;
    execution_admission_qualified = false;
    full_system_admission_qualified = false;
  });
in
  mkDerivation {
    pname = "gem5-arm-linux-network-lifecycle-check";
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
      native
      gem5-aarch64-linux
      gem5-aarch64-linux-device-fixture
      gem5-aarch64-bootloader
      dmtcp
      gem5-process-custody
    ];
    phases = [
      {
        name = "configure";
        script = ''
          mkdir helper-source
          ${copyHelpers}
        '';
      }
      {
        name = "check";
        script = ''
          export PYTHONDONTWRITEBYTECODE=1
          ${python3}/bin/python3 -B helper-source/closed-network-loopback-check.py
          ${python3}/bin/python3 -B helper-source/native-controller-arm-network-model-check.py
          ${python3}/bin/python3 -B helper-source/closed-memory-block-check.py
          ${python3}/bin/python3 -B helper-source/native-controller-arm-block-model-check.py
          ${python3}/bin/python3 -B helper-source/native-controller-arm-devices-model-check.py
          ${python3}/bin/python3 -B helper-source/device-archive-custody-check.py
          ${python3}/bin/python3 -B helper-source/causal-device-projection-check.py
          export LD_LIBRARY_PATH="${abseil-cpp}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          witness_root="$(mktemp -d /tmp/gem5-arm-network-lifecycle.XXXXXXXX)"
          if ! ${coreutils}/bin/timeout 1200 ${python3}/bin/python3 -B \
            helper-source/native-controller-arm-network-check.py \
            ${native}/bin/gem5 "$PWD/helper-source" "$witness_root/native" \
            ${native}/share/gem5/configs \
            ${gem5-aarch64-linux}/boot/vmlinux \
            ${gem5-aarch64-linux-device-fixture}/initrd.img \
            ${gem5-aarch64-bootloader}/share/gem5/bootloader/boot_v2.arm64 \
            ${dmtcp} ${gem5-process-custody}/lib/libcrucible-resource-custody.so \
            > native-device-check.log 2>&1; then
            cat native-device-check.log
            exit 1
          fi
          cp "$witness_root/native/result.json" summary.json
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/checks" "$out/share/gem5/arm-device-proof-source"
          cp summary.json "$out/share/checks/arm-linux-network-lifecycle.json"
          cp ${record} "$out/share/gem5/arm-device-proof-source/manifest.json"
          cp helper-source/*.py "$out/share/gem5/arm-device-proof-source/"
          cp ${./gem5-patches/native-controller-device.patch} "$out/share/gem5/arm-device-proof-source/controller.patch"
          cp ${./_gem5/controller-source-delta.json} "$out/share/gem5/arm-device-proof-source/controller-source-delta.json"
          cp ${./gem5-arm-linux-network-lifecycle-check.nix} "$out/share/gem5/arm-device-proof-source/recipe.nix"
        '';
      }
    ];
    meta = {
      description = "Preserves actual Linux Ethernet TX, owned future native RX and original finite disk custody through source deletion and two independently audited incoming-only readback continuations";
      license = "MIT";
    };
  }
