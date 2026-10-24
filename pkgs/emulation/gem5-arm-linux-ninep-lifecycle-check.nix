##! Closed ARM Linux device/image foundation; no ordinary-node admission
{
  mkDerivation,
  gem5-closed-block-foundation,
  gem5-aarch64-linux,
  gem5-aarch64-linux-device-fixture,
  gem5-aarch64-bootloader,
  dmtcp,
  gem5-process-custody,
  python3,
  coreutils,
  abseil-cpp,
}: let
  native = gem5-closed-block-foundation;
  helpers = {
    "native-controller-device.py" = ./_gem5/native-controller-device.py;
    "native-controller-models.py" = ./_gem5/native-controller-models.py;
    "native-controller-arm-model.py" = ./_gem5/native-controller-arm-model.py;
    "native-controller-arm-devices.py" = ./_gem5/native-controller-arm-devices.py;
    "native-controller-arm-devices-model.py" = ./_gem5/native-controller-arm-devices-model.py;
    "native-controller-arm-devices-model-check.py" = ./_gem5/native-controller-arm-devices-model-check.py;
    "native-controller-arm-ninep-check.py" = ./_gem5/native-controller-arm-ninep-check.py;
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
    "native-controller-arm-ninep-model.py" = ./_gem5/native-controller-arm-ninep-model.py;
    "native-controller-arm-ninep-model-check.py" = ./_gem5/native-controller-arm-ninep-model-check.py;
    "native-controller-arm-ninep-board.py" = ./_gem5/native-controller-arm-ninep-board.py;
    "native-controller-arm-ninep.py" = ./_gem5/native-controller-arm-ninep.py;
    "closed-memory-ninep-bounded.py" = ./_gem5/closed-memory-ninep-bounded.py;
    "closed-memory-ninep-bounded-check.py" = ./_gem5/closed-memory-ninep-bounded-check.py;
    "finite-ninep-bounded-fixture.py" = ./_gem5/finite-ninep-bounded-fixture.py;
    "closed-ninep-native-check.py" = ./_gem5/closed-ninep-native-check.py;
    "closed-ninep-image-check.py" = ./_gem5/closed-ninep-image-check.py;
    "closed-ninep-process-image-audit.py" = ./_gem5/closed-ninep-process-image-audit.py;
    "closed-ninep-process-image-policy-check.py" = ./_gem5/closed-ninep-process-image-policy-check.py;
    "process-image-audit-core.py" = ./_gem5/process-image-audit-core.py;
  };
  names = builtins.attrNames helpers;
  copyHelpers = builtins.concatStringsSep "\n" (map
    (name: "cp ${helpers.${name}} helper-source/${name}")
    names);
  record = builtins.toFile "gem5-arm-device-proof-source.json" (builtins.toJSON {
    schema = "crucible.gem5.arm-device-proof-source.v1";
    recipe_sha256 = builtins.hashFile "sha256" ./gem5-arm-linux-ninep-lifecycle-check.nix;
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
    pname = "gem5-arm-linux-ninep-lifecycle-check";
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
          ${python3}/bin/python3 -B helper-source/closed-memory-ninep-bounded-check.py
          ${python3}/bin/python3 -B helper-source/native-controller-arm-ninep-model-check.py
          ${python3}/bin/python3 -B helper-source/closed-ninep-process-image-policy-check.py
          ${python3}/bin/python3 -B helper-source/closed-memory-block-check.py
          ${python3}/bin/python3 -B helper-source/native-controller-arm-block-model-check.py
          ${python3}/bin/python3 -B helper-source/native-controller-arm-devices-model-check.py
          ${python3}/bin/python3 -B helper-source/device-archive-custody-check.py
          ${python3}/bin/python3 -B helper-source/causal-device-projection-check.py
          export LD_LIBRARY_PATH="${abseil-cpp}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          for mode in enabled disabled; do
            ${coreutils}/bin/timeout 30 ${native}/bin/gem5 --listener-mode=off \
              --outdir="$PWD/ninep-primitive-$mode" helper-source/closed-ninep-native-check.py "$mode" \
              > "ninep-primitive-$mode.log" 2>&1
          done
          ${python3}/bin/python3 -B - <<'PY_NATIVE'
          import json
          from pathlib import Path
          for mode in ('enabled', 'disabled'):
              path = Path(f'ninep-primitive-{mode}.log')
              if path.stat().st_size > 1024 * 1024:
                  raise ValueError('native 9p primitive evidence exceeds finite pre-read credit')
              rows = [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]
              matches = [row for row in rows if row.get('schema') == 'crucible.gem5.closed-ninep-native-boundary-mechanism.v1']
              if len(matches) != 1 or matches[0].get('mode') != mode:
                  raise ValueError('native 9p primitive original result is missing or ambiguous')
              Path(f'ninep-primitive-{mode}.json').write_text(
                  json.dumps(matches[0], sort_keys=True, separators=(',', ':')) + '\n')
          PY_NATIVE
          witness_root="$(mktemp -d /tmp/gem5-arm-ninep-lifecycle.XXXXXXXX)"
          if ! ${coreutils}/bin/timeout 1200 ${python3}/bin/python3 -B \
            helper-source/native-controller-arm-ninep-check.py \
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
          cp summary.json "$out/share/checks/arm-linux-ninep-lifecycle.json"
          cp ninep-primitive-enabled.json "$out/share/checks/ninep-native-enabled.json"
          cp ninep-primitive-disabled.json "$out/share/checks/ninep-native-disabled.json"
          cp ${record} "$out/share/gem5/arm-device-proof-source/manifest.json"
          cp helper-source/*.py "$out/share/gem5/arm-device-proof-source/"
          cp ${./gem5-patches/native-controller-device.patch} "$out/share/gem5/arm-device-proof-source/controller.patch"
          cp ${./_gem5/controller-source-delta.json} "$out/share/gem5/arm-device-proof-source/controller-source-delta.json"
          cp ${./gem5-arm-linux-ninep-lifecycle-check.nix} "$out/share/gem5/arm-device-proof-source/recipe.nix"
        '';
      }
    ];
    meta = {
      description = "Preserves actual Linux 9p write, owned future tree mutation and original finite disk custody through source deletion and two independently audited write/flush/readback continuations";
      license = "MIT";
    };
  }
