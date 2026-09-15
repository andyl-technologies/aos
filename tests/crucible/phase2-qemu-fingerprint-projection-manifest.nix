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
                    (keys | sort) == (["domain", "id", "instance",
                      "projection-schema", "projection-version",
                      "vmsd-name", "vmsd-version"] | sort) and
                    .["projection-version"] == 1 and
                    (.id | length) > 0 and
                    (.["vmsd-name"] | length) > 0 and
                    (.["projection-schema"] |
                      startswith("crucible.qemu.") and endswith(".v1")))
                ' "$out/$name.json" > /dev/null || {
                  cat "$out/$name.json" >&2
                  cat "$out/$name.stderr" >&2
                  return 1
                }
            }

            query_manifest q35-machine 37 \
              20c4c8aa5d8f01524109f8992ae9fa781079672bd0ab20154a765b314f76bcfd \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest aarch64-machine 16 \
              a997f893fbcf9b18aac4489acd934ec21f42b52f7bea273fb589b088adf73009 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel tcg -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1

            query_manifest q35-production-fault 38 \
              b16a021575e8531db6113dca25b8e81d4030ac83ef71e412bb9a0f1608cac716 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-fault-smp4 47 \
              3e1a188d6e5e81c1c219b89ddd807cbe7c8d2f509da9f9e50519a7f2b6a52a93 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault 17 \
              56416e60b98c89d742067f6b778065f4703067f8194844522188af9e2567d398 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-fault-smp4 23 \
              2b853f147b00af4c4298cb851e8478ca83cf9a1533122a35f4b0a3c18d129a1c \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 -smp 4 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-9p 39 \
              657bf3e722902f9ef7580beaffe68cb4acc418e26c9544a3f872301cf9b8b481 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-network 39 \
              f21cd0d806ba275f7a302528f60ecf47da798b3ee447b8f4570004bbe13d36b3 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-accelerator 39 \
              0e824c538872a2e77e3956ce9ac67e62293b39a660eff9f7f197dfc43859b063 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-debug-channel 39 \
              856fdd6c566190178b9e6da9435da0481ba0efdacbea6c3f6366db6d42012460 \
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
              51a4a47e4c94b15c43b55683a33cd2f628880950402a898a190a87eacb74e80a \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-shmem 19 \
              1d8179e7847c2a23b6e8159e14afb0950c3ce93eb368a81e3426796b34430e31 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 \
              -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-root-block 39 \
              697a8d16cfb7f7a453c538ea3e268119361a0791c83f241436cde89fc934e1cf \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest q35-production-console 39 \
              60a8ce4944fa66889b41218f230846c544beefb787dc74b3f94f128cdd3fe129 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-root-block 18 \
              f22a3f78f9453d243066845a0a9e71fd5c26de01d02bfb03e144aba2d6b1fc74 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -blockdev driver=null-co,node-name=crucible-root \
              -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-9p 18 \
              b49b0db1e368653d70230a6a91c0c7bc8274d2ae80f845deafdd601512714014 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -fsdev synth,id=crucible-9p-fsdev0 \
              -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-network 18 \
              bd59b66e7169aafd1b35babd13a6df3a4e12be190429ddb6fd43ba44c1deee5f \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -netdev hubport,id=crucible-netdev0,hubid=0 \
              -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-accelerator 18 \
              65d8d1b73f7464350b6d85c0c516835aed57a9a4ea741cf6185bcbb8df3214cb \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-debug-channel 18 \
              0774a651710c0400e33a0aa93978e67db3660b012eb111ead204c751566e1b76 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -chardev null,id=crucible-debug-activation \
              -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 \
              -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug \
              -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-console 17 \
              56416e60b98c89d742067f6b778065f4703067f8194844522188af9e2567d398 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              -device virtio-rng-pci,bus=pcie.0,addr=0x1 \
              -plugin ./fault-manifest-plugin.so

            common_all_devices='-device virtio-rng-pci,bus=pcie.0,addr=0x1 -blockdev driver=null-co,node-name=crucible-root -device virtio-blk-pci,drive=crucible-root,id=crucible-root-device,bus=pcie.0,addr=0x2 -blockdev driver=crucible-shmem,node-name=crucible-blk0,size=1048576 -device virtio-blk-pci,drive=crucible-blk0,id=crucible-blk-device0,ioeventfd=off,bus=pcie.0,addr=0x3 -fsdev synth,id=crucible-9p-fsdev0 -device virtio-9p-pci,fsdev=crucible-9p-fsdev0,mount_tag=crucible,id=crucible-9p-device0,bus=pcie.0,addr=0x4 -netdev hubport,id=crucible-netdev0,hubid=0 -device virtio-net-pci,netdev=crucible-netdev0,id=crucible-net-device0,mac=52:54:00:12:34:56,bus=pcie.0,addr=0x5 -device virtio-crucible-accelerator-pci,id=crucible-accelerator0,disable-legacy=on,bus=pcie.0,addr=0x6 -chardev null,id=crucible-debug-activation -device virtio-serial-pci,id=crucible-debug-serial,bus=pcie.0,addr=0x7 -device virtserialport,bus=crucible-debug-serial.0,chardev=crucible-debug-activation,name=org.aos.crucible.debug'

            # Word splitting is deliberate: every token above is one canonical
            # QEMU argv element and contains no whitespace.
            query_manifest q35-production-all-combined 46 \
              aca862dd10cea0ecee1421ac1dd7f922c2ed153a424fb7d6e3e52e9649774f55 \
              ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc-q35-9.2 -cpu qemu64,-rdrand,-rdseed \
              -accel sim,thread=single -icount shift=0,sleep=off \
              -nodefaults -no-user-config -display none -serial null \
              $common_all_devices -plugin ./fault-manifest-plugin.so

            query_manifest aarch64-production-all-combined 24 \
              93cbf8ca6b9d02ded1d71ba48ea9fecd953d92f558a695643054cbed5e7c1bdc \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              -machine virt-9.2 -cpu cortex-a57 \
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
                  "20c4c8aa5d8f01524109f8992ae9fa781079672bd0ab20154a765b314f76bcfd")
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
            q35_machine_digest=20c4c8aa5d8f01524109f8992ae9fa781079672bd0ab20154a765b314f76bcfd
            aarch64_machine_sections=16
            aarch64_machine_digest=a997f893fbcf9b18aac4489acd934ec21f42b52f7bea273fb589b088adf73009
            q35_production_fault_sections=38
            q35_production_fault_digest=b16a021575e8531db6113dca25b8e81d4030ac83ef71e412bb9a0f1608cac716
            q35_production_fault_smp4_sections=47
            q35_production_fault_smp4_digest=3e1a188d6e5e81c1c219b89ddd807cbe7c8d2f509da9f9e50519a7f2b6a52a93
            aarch64_production_fault_sections=17
            aarch64_production_fault_digest=56416e60b98c89d742067f6b778065f4703067f8194844522188af9e2567d398
            aarch64_production_fault_smp4_sections=23
            aarch64_production_fault_smp4_digest=2b853f147b00af4c4298cb851e8478ca83cf9a1533122a35f4b0a3c18d129a1c
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
            q35_production_all_combined_digest=aca862dd10cea0ecee1421ac1dd7f922c2ed153a424fb7d6e3e52e9649774f55
            aarch64_production_all_combined_sections=24
            aarch64_production_all_combined_digest=93cbf8ca6b9d02ded1d71ba48ea9fecd953d92f558a695643054cbed5e7c1bdc
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
