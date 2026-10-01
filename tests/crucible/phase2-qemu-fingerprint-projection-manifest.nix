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
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.glib
        pkgs.glib.dev
        pkgs.jq
        pkgs.pkg-config
        pkgs.rust
        pkgs.sed
        pkgs.sqlite
        qemuPackage
      ];
      runtimeDeps = [pkgs.sqlite];

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
            export RUSTFLAGS="-C link-arg=-Wl,-rpath,${pkgs.sqlite}/lib"
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
            # The input queue registers at sim machine-done: ordinary TCG omits
            # it, and sim profiles place it after the realized device rows.
            # The preemption section remains in QMP's registry outside sim;
            # its VMState needed predicate only controls serialized state.
            query_manifest q35-machine 38 \
              4122e2e3244393e6fcc1b803c892c582d4d93271210d6061d4409226515564a1 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest aarch64-machine 17 \
              6322a0e9676ba933394062bfc10cb1f32cfae930a0d7649bb8a70208376760ed \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest q35-production-fault 40 \
              3a9543b78a836778a513700fb5703bed862890c96d27ee440b9c18064579c082 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-fault-smp4 49 \
              864b67fdaba65ffb7a261f41cb4ad85625f6fdc11e638cad8561ca60bd914b7a \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault 19 \
              f3a98c8815ffaf4d58a25a7e31aa8ed5d2b6e3b9d02ee2a4286e4d7532e5277a \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault-smp4 25 \
              7d05885eed659714ed7c7c2d78450b38d67244e9c711b4ad55852113600e4313 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-9p 41 \
              acd0b5f4e6cfe2e8b2d2f14213ec3511fc80db9fe7e8dc54564f660217e37ad6 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-network 41 \
              cac592d34ebd604c51523dafc9469bfce781eaa11bdad93a24698ab10968da54 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-accelerator 41 \
              275dfeda439a9d2e6ebfde729fd0fe51f104587b3a9cc34f0324e0672c6dbd93 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-debug-channel 41 \
              d0824726a940f6622171b22c542e166ab470f076ab1b0475c77c8bb5bc3f4dc0 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -chardev null,id=crucible-debug-activation \
              -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 \
              -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-shmem 42 \
              9c35e4a07d738d707d7c2e1c4e70a3d1f09d28a3c18ec61817e5a7167f82d011 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-shmem 21 \
              ffbabf90cf454ec4d0d3ba292e6b6918d4178ed0a77e29e07d4e89b88f6b6de4 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-root-block 41 \
              9104ed28b75412e0ef6099c38dad0a8a13515f014a796cf73aa1f8d30c20b1fa \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-console 41 \
              cdc18efdde810f55a86c2463b6336b80163f5b87d585c4038106ec08ec1ddde4 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-root-block 20 \
              ff0e7d4d24fc5989aadcab135709aff2d59f8ff877ccf1ae009250ca7440374f \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-9p 20 \
              bc2f45f4b3fae6d5dd77a0cbfc37f96474ea465461580c931af315d557874eed \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-network 20 \
              57536723e2faba28db6b2cd0f87ff7a2dd1b4c360cd18a939cefbd5cce609e51 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-accelerator 20 \
              08671a0d91140b1c13e6ce1169f5390b6dd6e459703c58072acf18ba97c40e86 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-debug-channel 20 \
              ed944adedcca07fd01fe0dea06a0eab4de68b4e2598f066dc08cf74f13969c83 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -chardev null,id=crucible-debug-activation \
              -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 \
              -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-console 19 \
              f3a98c8815ffaf4d58a25a7e31aa8ed5d2b6e3b9d02ee2a4286e4d7532e5277a \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            common_all_devices='-device virtio-rng-pci,bus=pcie.0,addr=0x1 -blockdev driver=null-co,node-name=crucible-root -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 -fsdev synth,id=crucible-9p-fsdev0 -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 -netdev hubport,id=crucible-netdev0,hubid=0 -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 -chardev null,id=crucible-debug-activation -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug'

            # Word splitting is deliberate: every token above is one canonical
            # QEMU argv element and contains no whitespace.
            query_manifest q35-production-all-combined 48 \
              daaa47b86ac8b2175feace991ee77001357222dbc54e9e39295097e9c23f5dea \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              $common_all_devices -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-all-combined 26 \
              c1f00e5b71f40bc7f45d525e3741674ace3407e27b021d6ab77df82e40ec982c \
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
            jq -e -s '
              any(.[]; .return.sections? == 37 and
                .return.digest? ==
                  "58641db5293b417611ab56558e90b9ad1e78349443d80bd8d25afe24d12f2ee3")
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
            q35_machine_digest=4122e2e3244393e6fcc1b803c892c582d4d93271210d6061d4409226515564a1
            aarch64_machine_sections=17
            aarch64_machine_digest=6322a0e9676ba933394062bfc10cb1f32cfae930a0d7649bb8a70208376760ed
            q35_production_fault_sections=40
            q35_production_fault_digest=3a9543b78a836778a513700fb5703bed862890c96d27ee440b9c18064579c082
            q35_production_fault_smp4_sections=49
            q35_production_fault_smp4_digest=864b67fdaba65ffb7a261f41cb4ad85625f6fdc11e638cad8561ca60bd914b7a
            aarch64_production_fault_sections=19
            aarch64_production_fault_digest=f3a98c8815ffaf4d58a25a7e31aa8ed5d2b6e3b9d02ee2a4286e4d7532e5277a
            aarch64_production_fault_smp4_sections=25
            aarch64_production_fault_smp4_digest=7d05885eed659714ed7c7c2d78450b38d67244e9c711b4ad55852113600e4313
            q35_production_9p_sections=41
            q35_production_network_sections=41
            q35_production_accelerator_sections=41
            q35_production_debug_channel_sections=41
            q35_production_shmem_sections=42
            aarch64_production_shmem_sections=21
            q35_production_root_block_sections=41
            q35_production_console_sections=41
            aarch64_production_root_block_sections=20
            aarch64_production_9p_sections=20
            aarch64_production_network_sections=20
            aarch64_production_accelerator_sections=20
            aarch64_production_debug_channel_sections=20
            q35_production_all_combined_sections=48
            q35_production_all_combined_digest=daaa47b86ac8b2175feace991ee77001357222dbc54e9e39295097e9c23f5dea
            aarch64_production_all_combined_sections=26
            aarch64_production_all_combined_digest=c1f00e5b71f40bc7f45d525e3741674ace3407e27b021d6ab77df82e40ec982c
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
