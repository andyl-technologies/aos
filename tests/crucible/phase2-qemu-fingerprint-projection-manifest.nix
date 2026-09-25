{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
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
      pname = "crucible-phase2-qemu-fingerprint-projection-manifest";
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
                --arg digest "$expected_digest" '
                  [.[] | select(.return.digest?) | .return] as $manifests |
                  ($manifests | length) == 1 and
                  $manifests[0]["schema-version"] == 4 and
                  $manifests[0].sections == $sections and
                  $manifests[0].digest == $digest and
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
            }

            # Pin the exact current ordered registry for each admitted launch.
            # A schema or VMState change requires comparing live QMP rows before
            # refreshing these digests.
            query_manifest q35-machine 37 \
              cdb8ea3b92edcc47de2bad72eb6f87e0dd5c28a983de35454da909d8a8b5a238 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest aarch64-machine 16 \
              ccbe4c76d92e441202ad41bd7140f737496bf623f5c95f8616273a64ce9e6ab3 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest q35-production-fault 38 \
              430c2e7afdf4fa82e629a3cf3ca6f957c6a1f832b616387ed6db27294f5aba2b \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-fault-smp4 47 \
              d7468d0ba15507bcf8ea4712c35ca1bbf8aa29384158e15fe72cf3c83cb18da6 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault 17 \
              11e7220ea3556953e9d220a44ca12c2b924b96d2abe9cc36ed99d3c5e23f2dd8 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault-smp4 23 \
              eea441a2858d5ca87e5569043f15b2a4bc660e5abb88cf18e4f79d1441b4783a \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-9p 39 \
              b7b86712f0b1f2295b1f9d0f86019f983392cfbe1d0c83458129bd664878a7f9 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-network 39 \
              eab3262b0890ac5a30c2299048a0e0b396bea0811ebc02388cc4fb97a9d727ba \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-accelerator 39 \
              4bbbb5638ab446a3cab5cca5f2b5e0d92261b094ed086a46ace614d421e4e60a \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-debug-channel 39 \
              8adc4e25f92db9b6c9af7ac91d4a1f43818ac63242ed299ea1d1a71020e17902 \
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
              dc69874f9228566f51c9609e401553cc1a4b44a043e3ae798005901ea2cc633a \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-shmem 19 \
              0151602e52b8ba5f9d6a09c7a8084c08c58d7ff12afaa39f72d5700b3536febb \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-root-block 39 \
              1f9d0fd2d23856690984e73b64501355d7307882bf739be92e346e14e7e11389 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-console 39 \
              b9921657673d6a739cb5908d199a98a4f2d3ed84206e1f1f2924030454dc8b34 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-root-block 18 \
              cbd0dd94c8fa4b63c2628b245b65c9a936846b326f2fefc63471ffd2c745ffcd \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-9p 18 \
              1fa22779e24ebe17752c0154b27076e66b15d11016002fb524bf74d88ee4f57a \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-network 18 \
              6ffff4b0587c49e796e6102b64421eb64c45528608931da8f480b04d6ca862b6 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-accelerator 18 \
              41e02f39b88d5e5410b4644682276c48340b228c62224a7f5cb02125d406e7b7 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-debug-channel 18 \
              38939e4fb8eb5c4c1c46d9cc1f50ba43ffac0da7c60af67bc72b8579532b2455 \
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
              11e7220ea3556953e9d220a44ca12c2b924b96d2abe9cc36ed99d3c5e23f2dd8 \
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
              d57f34227737d735e002cca941dd96e718d7f959ee3752a6272dc1ee4c944557 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              $common_all_devices -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-all-combined 24 \
              74b2045d924bb2fbe917593f461215d2d3296258ff97257433d50eac22783ecb \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57,pmu=off \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              $common_all_devices -plugin ./fault-manifest-plugin.so

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
                  "aaed485b647708698c925c9084891abe46b9958f85b56f8057efabcd53f38c3e")
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

            cat > "$out/result" <<'RESULT'
            PASS
            gate=gate:qemu-fingerprint-projection-manifest
            schema_version=4
            q35_machine_sections=37
            q35_machine_digest=aaed485b647708698c925c9084891abe46b9958f85b56f8057efabcd53f38c3e
            aarch64_machine_sections=16
            aarch64_machine_digest=eae78ac9196a112bb3bc646fbe4f7806b6651f6e888c755a5486a07a13c6d7bb
            q35_production_fault_sections=38
            q35_production_fault_digest=716305da24004b0104918d95895908e999ed1111d58c86abdb0d84ab0d83cacb
            q35_production_fault_smp4_sections=47
            q35_production_fault_smp4_digest=885e9d500165787be73a108c416e81f4170d6a6f34c8d3a8538c5b218014753b
            aarch64_production_fault_sections=17
            aarch64_production_fault_digest=44f981e197b621f80d6f4adb428b94d0a61078fae283f99cc2a42d6470da8290
            aarch64_production_fault_smp4_sections=23
            aarch64_production_fault_smp4_digest=e8ed8529347f281a6718a3c9b48accfdb74026e15d4b960f5f847a7f3290a12b
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
            q35_production_all_combined_digest=8714b7496ed5577a3952ec7e9461b873afdd60036e919f492e48ad331938c5de
            aarch64_production_all_combined_sections=24
            aarch64_production_all_combined_digest=20298038469471f62511c26ad7e992e6da604191f5e75c5d6453710513786e24
            missing_expected_device_changes_manifest=true
            unexpected_unowned_device_fails_closed=true
            fixed_pci_address_collision_rejected=true
            launch_derived_manifest_catalog_tested=true
            integrated_fixed_configuration_runner=true
            RESULT
          '';
        }
      ];
    }
