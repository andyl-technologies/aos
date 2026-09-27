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
              94adff71fe3c733555b09a011aba7145d4568e75a9c21295067c9667b32df54d \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest aarch64-machine 17 \
              cc04633a677c8220cc2933c21953b78627e5564d10229909bd304b91b94b7ce6 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest q35-production-fault 40 \
              a4a03ede093eacfaa1c16996ed8247656d907205a41243d7caad045b253cbc78 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-fault-smp4 49 \
              9a76f574fa41517627871b7d9393b8ec91a544414bca76488eeea375648a450e \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault 19 \
              be9cf23506b592c68f6d85d52a93ba85fbc1404d07583a6a5dd6892b23d37e54 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault-smp4 25 \
              d323823b6af3491e3f475a7b97ea08a565775f28217b342fe7e923fa2611d016 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-9p 41 \
              aa787f6df04ec1f2c3355902d9c55c6a280cd121eb8237d8f05bb5bff6dfb627 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-network 41 \
              12b939a7bcd4d961e315ba4018653d66779ba73a573e28e4ecd1b325a49bd459 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-accelerator 41 \
              021ff4dca86901d9007aacacf846b09acb02af1553bb7f20fab1a8c5ee59640d \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-debug-channel 41 \
              7663a0a9a981012a21ed3d2a701cc9eca9c4fbd2bab9d7be1f8f0cf6ed7351a3 \
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
              8196a0e9cdbecedba7a996806460c08f52176dc2f7e45c1d4a9f789c9d8a86c3 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-shmem 21 \
              aa86fdc41053723472192ec26aa11fb9e9408293d255680a0c69cae9f5e4d471 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-root-block 41 \
              0a7fa68c7694f3ffe064e608dfbb24323345cb08d65a2a6e7607710e1cfd40b3 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-console 41 \
              560870d25305ba7aaac26ff78bc360fbfb2254549019aefa04569fe82ad8dad0 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-root-block 20 \
              610d1c312766a9af7abc52b60bdcaf0df996d6cc4450bf52d2fb78dde337a8bf \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-9p 20 \
              75858d1cd749aadb1ea5b18309b53b6010c41e6bbaf412081c69d27eea17f791 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-network 20 \
              9173e95247c2f567cbe801cae433a49f644bc67d74e8c34e2ff1017ebd3bac30 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-accelerator 20 \
              358c18227a5f454e699ff50395966e1223bd596c53029d3b45364f61ba50e95d \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-debug-channel 20 \
              3d59cfbb507f6c71225e71844d48799d88f58af3b42bc02448880f957b5136d2 \
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
              be9cf23506b592c68f6d85d52a93ba85fbc1404d07583a6a5dd6892b23d37e54 \
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
              d8d67ae0a2b23d3511a65977433d24c33b195207a9fb0f8577037159739243bb \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              $common_all_devices -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-all-combined 26 \
              ecdcb8fa549e4a1842102353836bfa546cf070e760b7f81280989120248a97c1 \
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
                  "8b2c359bb48ee1791217fbeb9b7ce16fda2318dfaf4f146bf2e42fa74a6ae048")
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
            q35_machine_digest=94adff71fe3c733555b09a011aba7145d4568e75a9c21295067c9667b32df54d
            aarch64_machine_sections=17
            aarch64_machine_digest=cc04633a677c8220cc2933c21953b78627e5564d10229909bd304b91b94b7ce6
            q35_production_fault_sections=40
            q35_production_fault_digest=a4a03ede093eacfaa1c16996ed8247656d907205a41243d7caad045b253cbc78
            q35_production_fault_smp4_sections=49
            q35_production_fault_smp4_digest=9a76f574fa41517627871b7d9393b8ec91a544414bca76488eeea375648a450e
            aarch64_production_fault_sections=19
            aarch64_production_fault_digest=be9cf23506b592c68f6d85d52a93ba85fbc1404d07583a6a5dd6892b23d37e54
            aarch64_production_fault_smp4_sections=25
            aarch64_production_fault_smp4_digest=d323823b6af3491e3f475a7b97ea08a565775f28217b342fe7e923fa2611d016
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
            q35_production_all_combined_digest=d8d67ae0a2b23d3511a65977433d24c33b195207a9fb0f8577037159739243bb
            aarch64_production_all_combined_sections=26
            aarch64_production_all_combined_digest=ecdcb8fa549e4a1842102353836bfa546cf070e760b7f81280989120248a97c1
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
