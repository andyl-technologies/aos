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

            refresh_mode=${if refreshMode then "true" else "false"}
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
            query_manifest q35-machine 37 \
              73e3b2e7a4a1f7e703ac033bcd81dbd8a30823440981297708e2bf8349b4eef1 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest aarch64-machine 16 \
              446f4a27ba84e9cacb8ff4af3a3cdad59d54a25161c193da3b721f8b454039bf \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest q35-production-fault 38 \
              3da2702fbc015ddfa80fae245591ff1a0618883cb0b602388b0333047725eb70 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-fault-smp4 47 \
              5d93b59f81fbefcdd586873ae8671aad302fa728e9e69b8b786be14f131a0f25 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault 17 \
              99312a031d2c73e11a24759b31eed6f14a684054a6bc2c4559a4125a9c809f11 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault-smp4 23 \
              ff9391617f0bfd8bd1d4c33319a410f128f300abef14b92d5ef216182cd51bc9 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-9p 39 \
              3f70b51197e2ec018d1cf16a306270d5e0d2eda15047e7bb9a2ad258bd7613a4 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-network 39 \
              b76342236099f4c6965721d1a98b997fbcdeade4d32eeff4dbe12709a47ef2df \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-accelerator 39 \
              a3a6a6f80e0e3e69182e828006d153f2403eb84a98bb07cfd24acc256c1673ad \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-debug-channel 39 \
              b6a2b837bf2f69ee086591477b32e2b4ab2ccc8d11c7a08ecfcbccb7d11a8a3f \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -chardev null,id=crucible-debug-activation \
              -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 \
              -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-shmem 40 \
              6304ce4229fc7a0e87df9e7d2517e98be846769d99b8e8a0763243b816941ea0 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-shmem 19 \
              57378cd0e391ec9b8bdd75c824982bc15f89eb3d15734e930ea4e6fff6d08410 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-root-block 39 \
              a8dc26d8b4dad20f32bb4363473971202c655304de2c29eaaea3835f132d9eef \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-console 39 \
              33357f54b9d8b5fe5345592ee42244f4cfeddb9cb97f11c437f779288f1e32a1 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-root-block 18 \
              40105c7c80a45cbeea199278c7aae6e8b6bc5820cf1bbfcd5728654e4b3c0444 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-9p 18 \
              e9c8d3c6d093e949f7a881148e647b5afcde80b75110bc67e0ae20067b143107 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-network 18 \
              ab375bc69a95a5b73f7bca076c6a3dbc8cfc4427031afaaba7cd4a00eb11fbdc \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-accelerator 18 \
              9a075b96f332e3c515cac6dc38aa925f6bad1e768d4509858c46b432f6ec7e0d \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-debug-channel 18 \
              de2f5aae573aa73ed8252f15e7f1d98b14e42094b0d863dbb582aaf2db1cead4 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -chardev null,id=crucible-debug-activation \
              -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 \
              -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-console 17 \
              99312a031d2c73e11a24759b31eed6f14a684054a6bc2c4559a4125a9c809f11 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            common_all_devices='-device virtio-rng-pci,bus=pcie.0,addr=0x1 -blockdev driver=null-co,node-name=crucible-root -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 -fsdev synth,id=crucible-9p-fsdev0 -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 -netdev hubport,id=crucible-netdev0,hubid=0 -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 -chardev null,id=crucible-debug-activation -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug'

            # Word splitting is deliberate: every token above is one canonical
            # QEMU argv element and contains no whitespace.
            query_manifest q35-production-all-combined 46 \
              afc340a1f09acd31bd929c74ae9477d83de295bf6f10b237f5051c18da159005 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              $common_all_devices -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-all-combined 24 \
              8e2f8f2be84db117988f768774e75f26483a5939e987f052c5ee0b1a236e2e0b \
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
              any(.[]; .return.sections? == 37 and
                .return.digest? ==
                  "73e3b2e7a4a1f7e703ac033bcd81dbd8a30823440981297708e2bf8349b4eef1")
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
            q35_machine_sections=37
            q35_machine_digest=73e3b2e7a4a1f7e703ac033bcd81dbd8a30823440981297708e2bf8349b4eef1
            aarch64_machine_sections=16
            aarch64_machine_digest=446f4a27ba84e9cacb8ff4af3a3cdad59d54a25161c193da3b721f8b454039bf
            q35_production_fault_sections=38
            q35_production_fault_digest=3da2702fbc015ddfa80fae245591ff1a0618883cb0b602388b0333047725eb70
            q35_production_fault_smp4_sections=47
            q35_production_fault_smp4_digest=5d93b59f81fbefcdd586873ae8671aad302fa728e9e69b8b786be14f131a0f25
            aarch64_production_fault_sections=17
            aarch64_production_fault_digest=99312a031d2c73e11a24759b31eed6f14a684054a6bc2c4559a4125a9c809f11
            aarch64_production_fault_smp4_sections=23
            aarch64_production_fault_smp4_digest=ff9391617f0bfd8bd1d4c33319a410f128f300abef14b92d5ef216182cd51bc9
            q35_production_9p_sections=39
            q35_production_network_sections=39
            q35_production_accelerator_sections=39
            q35_production_debug_channel_sections=39
            q35_production_shmem_sections=40
            aarch64_production_shmem_sections=19
            q35_production_root_block_sections=39
            q35_production_console_sections=39
            aarch64_production_root_block_sections=18
            aarch64_production_9p_sections=18
            aarch64_production_network_sections=18
            aarch64_production_accelerator_sections=18
            aarch64_production_debug_channel_sections=18
            q35_production_all_combined_sections=46
            q35_production_all_combined_digest=afc340a1f09acd31bd929c74ae9477d83de295bf6f10b237f5051c18da159005
            aarch64_production_all_combined_sections=24
            aarch64_production_all_combined_digest=8e2f8f2be84db117988f768774e75f26483a5939e987f052c5ee0b1a236e2e0b
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
