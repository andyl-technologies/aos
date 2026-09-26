{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  # To audit a pin refresh, set BASELINE_MANIFESTS to this gate's successful
  # output from the prior revision and run:
  #
  # BASELINE_MANIFESTS=/nix/store/... nix-build --no-out-link --expr '
  #   let repo = import ./. {}; in import
  #   ./tests/crucible/phase2-qemu-fingerprint-projection-manifest.nix {
  #     inherit (repo) pkgs lib; refreshMode = true;
  #     baselineManifests = builtins.storePath
  #       (builtins.getEnv "BASELINE_MANIFESTS");
  #   }'
  #
  # Review manifest-inventory.tsv and manifest-row-diff.tsv before changing
  # the fail-closed pins used by the normal check attribute.
  refreshMode ? false,
  baselineManifests ? null,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  patchSource = builtins.readFile (
    ../../pkgs/emulation/qemu-patches + "/${atomicPatch.file}"
  );
  failures = failuresFor "pkgs/emulation/qemu-patches" patchSource [
    {
      label = "projection manifest QMP query";
      needle = "query-crucible-fingerprint-projection-manifest";
    }
    {
      label = "projection schema digest";
      needle = "qemu_fingerprint_projection_schema_sha256";
    }
  ];
in
  if failures != []
  then throw "Crucible fingerprint projection manifest gate failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname =
        "crucible-phase2-qemu-fingerprint-projection-manifest"
        + lib.optionalString refreshMode "-refresh";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.glib
        pkgs.glib.dev
        pkgs.jq
        pkgs.pkg-config
        pkgs.rust
        pkgs.sed
        qemuPackage
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
          '';
        }
        {
          name = "configure-rust";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            mkdir -p source/.cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > source/.cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > source/.cargo/config.toml
            fi
          '';
        }
        {
          name = "verify-launch-derived-catalog";
          script = ''
            cd source
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/fingerprint-projection-manifest-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              fingerprint_projection \
              -- --test-threads=1
            cd ..
          '';
        }
        {
          name = "build-fault-manifest-plugin";
          script = ''
            set -eu

            "$CC" -shared -fPIC -Wall -Wextra -Werror \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-fingerprint-projection-manifest.c} \
              -o fault-manifest-plugin.so \
              $(pkg-config --libs glib-2.0)
          '';
        }
        {
          name = "verify-exact-projection-manifests";
          script = ''
            set -eu
            mkdir -p "$out"

            refresh_mode=${
              if refreshMode
              then "true"
              else "false"
            }
            baseline_dir=${
              if baselineManifests == null
              then "''"
              else lib.escapeShellArg (toString baselineManifests)
            }
            printf '%b\n' \
              'profile\texpected_sections\tactual_sections\texpected_digest\tactual_digest' \
              > "$out/manifest-inventory.tsv"
            printf '%b\n' \
              'profile\trow_index\tchange\told_identity\tnew_identity\told_vmsd_version\tnew_vmsd_version\told_projection_version\tnew_projection_version\told_projection_schema\tnew_projection_schema' \
              > "$out/manifest-row-diff.tsv"

            query_manifest() {
              name="$1"
              expected_sections="$2"
              expected_digest="$3"
              qemu="$4"
              shift 4

              {
                printf '%s\n' '{"execute":"qmp_capabilities"}'
                printf '%s\n' \
                  '{"execute":"query-crucible-fingerprint-projection-manifest"}'
                printf '%s\n' '{"execute":"quit"}'
              } | timeout -k 5 30 "$qemu" "$@" -S -qmp stdio \
                > "$out/$name.json" 2> "$out/$name.stderr"

              jq -e -s \
                --argjson sections "$expected_sections" \
                '
                  [.[] | select(.return.digest?) | .return] as $manifests |
                  ($manifests | length) == 1 and
                  $manifests[0]["schema-version"] == 4 and
                  $manifests[0].sections == $sections and
                  ($manifests[0].rows | length) == $sections and
                  all($manifests[0].rows[];
                    . as $row |
                    (keys | sort) == (["domain", "id", "instance",
                      "projection-schema", "projection-version",
                      "vmsd-name", "vmsd-version"] | sort) and
                    ($row["projection-version"] |
                      type == "number" and . >= 1) and
                    ($row.id | length) > 0 and
                    ($row["vmsd-name"] | length) > 0 and
                    ($row["projection-schema"] |
                      startswith("crucible.qemu.") and
                      endswith(".v" +
                        ($row["projection-version"] | tostring))))
                ' "$out/$name.json" > /dev/null || {
                  cat "$out/$name.json" >&2
                  cat "$out/$name.stderr" >&2
                  return 1
                }

              jq -e -s '[.[] | select(.return.digest?) | .return][0]' \
                "$out/$name.json" > "$out/$name.manifest.json"
              actual_sections=$(jq -r '.sections' "$out/$name.manifest.json")
              actual_digest=$(jq -r '.digest' "$out/$name.manifest.json")
              printf '%s\t%s\t%s\t%s\t%s\n' \
                "$name" "$expected_sections" "$actual_sections" \
                "$expected_digest" "$actual_digest" \
                >> "$out/manifest-inventory.tsv"

              if [ "$refresh_mode" = false ] && \
                [ "$actual_digest" != "$expected_digest" ]; then
                echo "$name: projection manifest digest mismatch" >&2
                echo "expected: $expected_digest" >&2
                echo "actual:   $actual_digest" >&2
                return 1
              fi

              if [ -n "$baseline_dir" ]; then
                jq -r -n \
                  --arg profile "$name" \
                  --slurpfile old "$baseline_dir/$name.json" \
                  --slurpfile new "$out/$name.manifest.json" '
                    def identity:
                      if . == null then "-"
                      else ([.domain, .id, .instance] | map(tostring) | join("/"))
                      end;
                    def value($name):
                      if . == null then "-" else (.[$name] | tostring) end;
                    ([$old[] | select(.return.digest?) | .return][0].rows) as $old_rows |
                    ($new[0].rows) as $new_rows |
                    range(0; ([$old_rows | length, $new_rows | length] | max)) as $index |
                    $old_rows[$index] as $old_row |
                    $new_rows[$index] as $new_row |
                    select($old_row != $new_row) |
                    [$profile, $index,
                      (if $old_row == null then "added"
                       elif $new_row == null then "removed"
                       else "changed"
                       end),
                      ($old_row | identity), ($new_row | identity),
                      ($old_row | value("vmsd-version")),
                      ($new_row | value("vmsd-version")),
                      ($old_row | value("projection-version")),
                      ($new_row | value("projection-version")),
                      ($old_row | value("projection-schema")),
                      ($new_row | value("projection-schema"))] | @tsv
                  ' >> "$out/manifest-row-diff.tsv"
              fi
            }

            # Pin the exact current ordered registry for each admitted launch.
            # A schema or VMState change requires comparing live QMP rows before
            # refreshing these digests.
            query_manifest q35-machine 38 \
              8d5dd529839adc86248c11b8a9afe55488a396b5b0e9597ecc0dae61b40c7a8a \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest aarch64-machine 17 \
              75ca96091e6678ad2215539781219223ea92ffbcc0456f9b60aed39b0fd6275d \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest q35-production-fault 39 \
              ee6010553d7a7d1a8ee4740b5f5f265f87539ab7ae492eaae5b8b84562d787bc \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-fault-smp4 48 \
              3a59da71dc11e4fe2f146574977be521b3cb160bc5aadd584cbef5afde25569f \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault 18 \
              9b3f3e1b09e31333bd6a44b4dd87b00f7cea73e06612be6ef2b41a65dd885c3a \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault-smp4 24 \
              394588ec1ff0acef7dba6260f9b54b30d9802b12971bd900423b96197f6e02fc \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-9p 40 \
              1866124fd12a36a8763720eb828a877eb3d0912e991bc28dbe44723ed4f38dee \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-network 40 \
              2c3740d47625dbc31d7a41f5eb86debc8d8fe81e615edcb0c135281ff9f110d3 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-accelerator 40 \
              7eb16644758ecd315f4ecda0e1897f0ba8602dbf06bb1883c011e1216470ccdc \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-debug-channel 40 \
              173d3bbe0bf11bf14852ac2558167d1ce0f6ec5351b501dba44a3a2b00e6f456 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -chardev null,id=crucible-debug-activation \
              -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 \
              -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-shmem 41 \
              2bcd22b67053628f727dc528fe8c975c73945110fb586ca8606d6983f52c22df \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-shmem 20 \
              39ebf9e4fa16d7eafaf0aba37f942726118d40a54e68c8bef631b66183686e58 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-root-block 40 \
              2401c40a0be0434fa2eff81563827ab628d8bb4f4c5c031a570f74a8c7ea9978 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-console 40 \
              ec8d6af8f3a9053014bcb7233ee812ee322ef8a95c0edb458abbb9cb0490f9f5 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-root-block 19 \
              2b3cabc00c363183a92e4e46318e03ac7c149dcc0d99a1d8231e38a1b17aafb2 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-9p 19 \
              6ef2b4e620b1f992c72caf412c48c3681a54e6e1ed9b4e85edd91900af55069e \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-network 19 \
              9eda9bdca979a1f73d21109b4df9c47399b10e6500760aa02039a5f7fd260ba4 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-accelerator 19 \
              349513048f5fe30a8c3f74d8cb0fb8acd49e53c5b7d8eb0b18b396b22c4592ac \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-debug-channel 19 \
              7685cb07ea243e5f8335baa1a6ce402940e0239ee29c56537ab831e521d09b49 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -chardev null,id=crucible-debug-activation \
              -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 \
              -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-console 18 \
              9b3f3e1b09e31333bd6a44b4dd87b00f7cea73e06612be6ef2b41a65dd885c3a \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            common_all_devices='-device virtio-rng-pci,bus=pcie.0,addr=0x1 -blockdev driver=null-co,node-name=crucible-root -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 -fsdev synth,id=crucible-9p-fsdev0 -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 -netdev hubport,id=crucible-netdev0,hubid=0 -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 -chardev null,id=crucible-debug-activation -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug'

            # Word splitting is deliberate: every token above is one canonical
            # QEMU argv element and contains no whitespace.
            query_manifest q35-production-all-combined 47 \
              3ae28b0d8f1e20fb1791f058a57a807b0dbe69c5c7349885e5bf6e9744a4b27c \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              $common_all_devices -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-all-combined 25 \
              a6461b16ae8c401844bb60ea8c0bff4b23ac4bc1a99413e4a85cf397e691fd64 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              $common_all_devices -plugin ./fault-manifest-plugin.so

            jq -R -s -e '
              split("\n") | map(select(length > 0)) as $lines |
              ($lines | length) == 23 and
              ($lines[0] | split("\t")) ==
                ["profile", "expected_sections", "actual_sections",
                  "expected_digest", "actual_digest"] and
              all($lines[1:][]; (split("\t") | length) == 5)
            ' "$out/manifest-inventory.tsv" > /dev/null
            jq -R -s -e '
              split("\n") | map(select(length > 0)) as $lines |
              ($lines | length) >= 1 and
              ($lines[0] | split("\t")) ==
                ["profile", "row_index", "change", "old_identity",
                  "new_identity", "old_vmsd_version", "new_vmsd_version",
                  "old_projection_version", "new_projection_version",
                  "old_projection_schema", "new_projection_schema"] and
              all($lines[1:][]; (split("\t") | length) == 11)
            ' "$out/manifest-row-diff.tsv" > /dev/null

            if timeout -k 5 30 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=collision-root \
              -device virtio-blk-pci,drive=collision-root,bus=pcie.0,addr=0x1 \
              -S -qmp stdio > "$out/q35-pci-collision.json" \
              2> "$out/q35-pci-collision.stderr"; then
              echo "QEMU admitted two devices at the same fixed PCI slot" >&2
              exit 1
            fi
            grep -F 'PCI: slot 1 function 0 not available' \
              "$out/q35-pci-collision.stderr" > /dev/null

            {
              printf '%s\n' '{"execute":"qmp_capabilities"}'
              printf '%s\n' \
                '{"execute":"query-crucible-fingerprint-projection-manifest"}'
              printf '%s\n' '{"execute":"quit"}'
            } | timeout -k 5 30 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel tcg -nodefaults -no-user-config -display none \
              -S -qmp stdio > "$out/q35-missing-rng.json"
            ! jq -e -s '
              any(.[]; .return.sections? == 38 and
                .return.digest? ==
                  "8d5dd529839adc86248c11b8a9afe55488a396b5b0e9597ecc0dae61b40c7a8a")
            ' "$out/q35-missing-rng.json" > /dev/null

            {
              printf '%s\n' '{"execute":"qmp_capabilities"}'
              printf '%s\n' \
                '{"execute":"query-crucible-fingerprint-projection-manifest"}'
              printf '%s\n' '{"execute":"quit"}'
            } | timeout -k 5 30 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel tcg -no-user-config -display none \
              -S -qmp stdio > "$out/q35-default-devices.json"
            jq -e -s 'any(.[]; .error?)' \
              "$out/q35-default-devices.json" > /dev/null

            if [ "$refresh_mode" = true ]; then
              cat > "$out/result" <<'RESULT'
            REFRESH_EVIDENCE
            gate=diagnostic:qemu-fingerprint-projection-manifest-refresh
            manifest_inventory=manifest-inventory.tsv
            manifest_row_diff=manifest-row-diff.tsv
            RESULT
            else
              cat > "$out/result" <<'RESULT'
            PASS
            gate=gate:qemu-fingerprint-projection-manifest
            schema_version=4
            q35_machine_sections=38
            q35_machine_digest=8d5dd529839adc86248c11b8a9afe55488a396b5b0e9597ecc0dae61b40c7a8a
            aarch64_machine_sections=17
            aarch64_machine_digest=75ca96091e6678ad2215539781219223ea92ffbcc0456f9b60aed39b0fd6275d
            q35_production_fault_sections=39
            q35_production_fault_digest=ee6010553d7a7d1a8ee4740b5f5f265f87539ab7ae492eaae5b8b84562d787bc
            q35_production_fault_smp4_sections=48
            q35_production_fault_smp4_digest=3a59da71dc11e4fe2f146574977be521b3cb160bc5aadd584cbef5afde25569f
            aarch64_production_fault_sections=18
            aarch64_production_fault_digest=9b3f3e1b09e31333bd6a44b4dd87b00f7cea73e06612be6ef2b41a65dd885c3a
            aarch64_production_fault_smp4_sections=24
            aarch64_production_fault_smp4_digest=394588ec1ff0acef7dba6260f9b54b30d9802b12971bd900423b96197f6e02fc
            q35_production_9p_sections=40
            q35_production_network_sections=40
            q35_production_accelerator_sections=40
            q35_production_debug_channel_sections=40
            q35_production_shmem_sections=41
            aarch64_production_shmem_sections=20
            q35_production_root_block_sections=40
            q35_production_console_sections=40
            aarch64_production_root_block_sections=19
            aarch64_production_9p_sections=19
            aarch64_production_network_sections=19
            aarch64_production_accelerator_sections=19
            aarch64_production_debug_channel_sections=19
            q35_production_all_combined_sections=47
            q35_production_all_combined_digest=3ae28b0d8f1e20fb1791f058a57a807b0dbe69c5c7349885e5bf6e9744a4b27c
            aarch64_production_all_combined_sections=25
            aarch64_production_all_combined_digest=a6461b16ae8c401844bb60ea8c0bff4b23ac4bc1a99413e4a85cf397e691fd64
            missing_expected_device_changes_manifest=true
            unexpected_unowned_device_fails_closed=true
            fixed_pci_address_collision_rejected=true
            launch_derived_manifest_catalog_tested=true
            integrated_fixed_configuration_runner=true
            RESULT
            fi
          '';
        }
      ];
    }
