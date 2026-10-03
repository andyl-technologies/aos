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
              4b3df49d1b4658595065b7c10ba0dac8d12b86552c64735da9aad02ce5d589f2 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-fault-smp4 49 \
              546ea4e3ec33f5be75999484b08f9c8e03d454cb98f4e4d26200aacbc6659096 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault 19 \
              15dd503eb70f3a9ab73bf9f79236a6703fa607d3da852d6d9f8ffcb5d0f68f88 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault-smp4 25 \
              e842bcaedece3242e0bbd334d19697265564388dcfe2c9ee2f8cb83c5097073d \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-9p 41 \
              78d73fce98f565b20c9de1f346aa8b8e71231f9c0ce895369c55cd9d7ac4f921 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-network 41 \
              b2ffeace2063a92223e606124058baafd105cdba1f5acac57dff494097ccf0cd \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-accelerator 41 \
              05239c861f4c1d9806ecd6bf6cca6c5e5ec007644653447392117fc86e0331df \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-debug-channel 41 \
              c85cbee5fb39329725bc22dd5335c2f8b562de5fe74dee9fccfe96847e76cb65 \
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
              90fa4b26dc5a199f7995ca9e4df2d47378e42679560f0dda99fb915c64b237bf \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-shmem 21 \
              b9fed81b883ac7788466bbb85a24811efb6458e5c8a57bb0bf78aa1c8d15b66a \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-root-block 41 \
              66c78c33101784f6a9cfaa7ac2e3f73f9046da32c8061e44797b733752d9abfe \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-console 41 \
              6b89a00025fbd8b321c66b374ac056c55746c3e1b92a82d3c75c12172d5c2267 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-root-block 20 \
              126b3ef8d5e5d9808fa41bea3f190fd963f4bb5052879fd352a3106a9798f5b9 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-9p 20 \
              f0a1a3c61739313f2be8f8d8b698488c3085ba8cd556629645a96a816d23e4b5 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-network 20 \
              25bdf71642fce594df8c3fcd8ef856e6a19cacebe8279bececc84a22116e6ad2 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-accelerator 20 \
              6d429026f2fe0d48e0cdf48a2a05ea55a450c5e2323fd191f8f39999a7fcf6ff \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-debug-channel 20 \
              88fbd79791e3540e9565a3e1f61ebec5611b1fba2e4389c2b6e3c7c5829606b9 \
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
              15dd503eb70f3a9ab73bf9f79236a6703fa607d3da852d6d9f8ffcb5d0f68f88 \
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
              3666338bd7d614539114f9c9e9b8a3220ac75093523ce65709b298ba6a927034 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              $common_all_devices -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-all-combined 26 \
              0645d338114ec5305f6dc68acb452339f6fe39ba14e7c6f41c1032eb2259c2bc \
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
            q35_production_fault_digest=4b3df49d1b4658595065b7c10ba0dac8d12b86552c64735da9aad02ce5d589f2
            q35_production_fault_smp4_sections=49
            q35_production_fault_smp4_digest=546ea4e3ec33f5be75999484b08f9c8e03d454cb98f4e4d26200aacbc6659096
            aarch64_production_fault_sections=19
            aarch64_production_fault_digest=15dd503eb70f3a9ab73bf9f79236a6703fa607d3da852d6d9f8ffcb5d0f68f88
            aarch64_production_fault_smp4_sections=25
            aarch64_production_fault_smp4_digest=e842bcaedece3242e0bbd334d19697265564388dcfe2c9ee2f8cb83c5097073d
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
            q35_production_all_combined_digest=3666338bd7d614539114f9c9e9b8a3220ac75093523ce65709b298ba6a927034
            aarch64_production_all_combined_sections=26
            aarch64_production_all_combined_digest=0645d338114ec5305f6dc68acb452339f6fe39ba14e7c6f41c1032eb2259c2bc
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
