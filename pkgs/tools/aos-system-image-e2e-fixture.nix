##! Runtime generator for the Hub system-image end-to-end fixture.
##!
##! This deliberately invokes the shipped `apr release` porcelain.  Its output
##! is the one producer artifact consumed by both the native and Worker Hub
##! launchers; neither consumer is allowed to synthesize package TOML, Git
##! objects, image receipts, or direct-delivery paths itself.
{
  mkDerivation,
  aos,
  bash,
  coreutils,
  dosfstools,
  gptfdisk,
  git,
  jq,
  mtools,
  qemu,
  systemd,
}: let
  rawImage =
    mkDerivation {
      pname = "aos-hub-e2e-image-raw";
      version = "2026.03";
      src = null;
      buildDeps = [coreutils dosfstools gptfdisk jq mtools];
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out"
            filename=aos-e2e.img
            truncate -s 32M "$out/$filename"
            ${gptfdisk}/bin/sgdisk \
              --new=1:2048:18431 --typecode=1:ef00 --change-name=1:esp \
              --new=2:18432:65502 --typecode=2:8304 --change-name=2:root-a \
              "$out/$filename"
            truncate -s 8M esp.fat
            ${dosfstools}/sbin/mkfs.fat esp.fat
            ${mtools}/bin/mmd -i esp.fat ::/EFI ::/EFI/Linux ::/EFI/systemd
            ${mtools}/bin/mcopy -i esp.fat \
              '${systemd}/lib/systemd/boot/efi/systemd-bootx64.efi' \
              ::/EFI/Linux/systemd-bootx64.efi
            ${mtools}/bin/mcopy -i esp.fat \
              '${systemd}/lib/systemd/boot/efi/systemd-bootx64.efi' \
              ::/EFI/systemd/systemd-bootx64.efi
            dd if=esp.fat of="$out/$filename" bs=512 seek=2048 conv=notrunc 2>/dev/null
            image_sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
            image_size=$(stat -c %s "$out/$filename")
            rootfs_sha256=$(dd if="$out/$filename" bs=512 skip=18432 count=47071 2>/dev/null | sha256sum | cut -d ' ' -f1)
            uki='${systemd}/lib/systemd/boot/efi/systemd-bootx64.efi'
            uki_sha256=$(sha256sum "$uki" | cut -d ' ' -f1)
            uki_size=$(stat -c %s "$uki")
            ${jq}/bin/jq -S -n \
              --arg format raw \
              --arg filename "$filename" \
              --arg sha256 "$image_sha256" \
              --arg objectKey "images/sha256/$image_sha256/$filename" \
              --arg mediaType application/vnd.aos.disk-image.raw \
              --arg logicalDiskSha256 "$image_sha256" \
              --arg rootfsSha256 "$rootfs_sha256" \
              --arg ukiSha256 "$uki_sha256" \
              --argjson byteSize "$image_size" \
              --argjson ukiSize "$uki_size" \
              --argjson targets '["bare-metal"]' \
              '{schemaVersion: 1, name: "aos-system", version: "2026.03",
                architecture: "x86_64", platform: "x86_64-linux",
                format: $format, filename: $filename, objectKey: $objectKey,
                mediaType: $mediaType, compression: "none", byteSize: $byteSize,
                virtualSizeBytes: $byteSize, sha256: $sha256,
                logicalDiskSha256: $logicalDiskSha256,
                rootfsSha256: $rootfsSha256,
                compatibleTargets: $targets, partitionTable: "gpt",
                kernelParams: "",
                partitions: [
                  {number: 1, label: "esp", type: "esp", filesystem: "vfat",
                    sizeMiB: 8, offsetBytes: 1048576, sizeBytes: 8388608},
                  {number: 2, label: "root-a", type: "root", filesystem: "fake",
                    sizeMiB: 22, offsetBytes: 9437184, sizeBytes: 24100352}],
                esp: {uki: "EFI/Linux/systemd-bootx64.efi",
                  sdBoot: "EFI/systemd/systemd-bootx64.efi"},
                uki: {filename: "systemd-bootx64.efi",
                  espPath: "EFI/Linux/systemd-bootx64.efi",
                  byteSize: $ukiSize, sha256: $ukiSha256,
                  signed: false, measured: false}}' > "$out/image-info.json"
          '';
        }
      ];
    };
  qcow2Image = mkDerivation {
    pname = "aos-hub-e2e-image-qcow2";
    version = "2026.03";
    src = null;
    buildDeps = [coreutils jq qemu rawImage];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out"
          filename=aos-e2e.qcow2
          ${qemu}/bin/qemu-img convert -f raw -O qcow2 '${rawImage}/aos-e2e.img' "$out/$filename"
          image_sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
          image_size=$(stat -c %s "$out/$filename")
          logical_sha256=$(sha256sum '${rawImage}/aos-e2e.img' | cut -d ' ' -f1)
          rootfs_sha256=$(dd if='${rawImage}/aos-e2e.img' bs=512 skip=18432 count=47071 2>/dev/null | sha256sum | cut -d ' ' -f1)
          uki='${systemd}/lib/systemd/boot/efi/systemd-bootx64.efi'
          uki_sha256=$(sha256sum "$uki" | cut -d ' ' -f1)
          uki_size=$(stat -c %s "$uki")
          ${jq}/bin/jq -S -n \
            --arg filename "$filename" --arg sha256 "$image_sha256" \
            --arg objectKey "images/sha256/$image_sha256/$filename" \
            --arg logicalDiskSha256 "$logical_sha256" \
            --arg rootfsSha256 "$rootfs_sha256" \
            --arg ukiSha256 "$uki_sha256" --argjson byteSize "$image_size" \
            --argjson ukiSize "$uki_size" \
            '{schemaVersion: 1, name: "aos-system", version: "2026.03",
              architecture: "x86_64", platform: "x86_64-linux", format: "qcow2",
              filename: $filename, objectKey: $objectKey,
              mediaType: "application/vnd.aos.disk-image.qcow2", compression: "none",
              byteSize: $byteSize, virtualSizeBytes: 33554432, sha256: $sha256,
              logicalDiskSha256: $logicalDiskSha256, rootfsSha256: $rootfsSha256,
              compatibleTargets: ["qemu-kvm", "openstack"], partitionTable: "gpt",
              kernelParams: "", partitions: [
                {number: 1, label: "esp", type: "esp", filesystem: "vfat",
                  sizeMiB: 8, offsetBytes: 1048576, sizeBytes: 8388608},
                {number: 2, label: "root-a", type: "root", filesystem: "fake",
                  sizeMiB: 22, offsetBytes: 9437184, sizeBytes: 24100352}],
              esp: {uki: "EFI/Linux/systemd-bootx64.efi",
                sdBoot: "EFI/systemd/systemd-bootx64.efi"},
              uki: {filename: "systemd-bootx64.efi",
                espPath: "EFI/Linux/systemd-bootx64.efi", byteSize: $ukiSize,
                sha256: $ukiSha256, signed: false, measured: false}}' > "$out/image-info.json"
        '';
      }
    ];
  };
  sysroot = mkDerivation {
    pname = "aos-hub-e2e-sysroot";
    version = "2026.03";
    src = null;
    buildDeps = [coreutils];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/etc"
          printf 'NAME=AOS Hub producer fixture\nVERSION=2026.03\n' > "$out/etc/aos-release"
        '';
      }
    ];
  };
in
  mkDerivation {
    pname = "aos-system-image-e2e-fixture";
    version = "0.1.0";
    src = null;
    runtimeDeps = [aos bash coreutils git rawImage qcow2Image sysroot systemd];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          cat > "$out/bin/aos-system-image-e2e-fixture" <<'EOF'
          #!${bash}/bin/bash
          set -euo pipefail
          if [ "$#" -ne 1 ]; then
            echo "usage: aos-system-image-e2e-fixture OUTPUT-DIRECTORY" >&2
            exit 2
          fi
          destination="$1"
          mkdir -p "$destination/home" "$destination/surface"
          export HOME="$destination/home"
          export USER=aos-image-producer
          export GIT_AUTHOR_NAME='AOS Image E2E'
          export GIT_AUTHOR_EMAIL='image-e2e@aos.invalid'
          export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME"
          export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"

          keygen="$(${aos}/bin/apr keys generate release --registry image-e2e 2>&1)"
          public_key=""
          while IFS= read -r line; do
            case "$line" in
              *"Public key: "*) public_key="''${line##*Public key: }"; break ;;
            esac
          done <<< "$keygen"
          test -n "$public_key"
          key="$HOME/.config/apm/keys/image-e2e-release.key"
          ${aos}/bin/apr create image-e2e --trust-key "$public_key" --key "$key"
          ${aos}/bin/apr release 2026.03 \
            --registry image-e2e \
            --store-path '${sysroot}' \
            --name aos-system \
            --platform x86_64-linux \
            --description 'AOS Hub producer-driven system-image fixture' \
            --license MIT \
            --maintainer image-e2e@aos.invalid \
            --sysroot \
            --image '${rawImage}' \
            --image-format raw \
            --image-uki '${systemd}/lib/systemd/boot/efi/systemd-bootx64.efi' \
            --image '${qcow2Image}' \
            --image-format qcow2 \
            --image-uki '${systemd}/lib/systemd/boot/efi/systemd-bootx64.efi' \
            --channel stable \
            --init-channel \
            --key "$key" \
            --cache-url http://127.0.0.1/aos-image-e2e-cache \
            --upload-url "file://$destination/surface"
          printf '%s\n' "$public_key" > "$destination/trust-key"
          printf '%s\n' '${rawImage}/aos-e2e.img' > "$destination/raw-path"
          printf '%s\n' '${qcow2Image}/aos-e2e.qcow2' > "$destination/qcow2-path"
          test -s "$destination/surface/info/refs"
          test -s "$destination/surface/HEAD"
          release_commit=""
          while IFS=$'\t' read -r oid ref; do
            case "$ref" in
              refs/tags/2026.03^\{\}) release_commit="$oid"; break ;;
            esac
          done < "$destination/surface/info/refs"
          test -n "$release_commit"
          test -s "$destination/surface/publication-receipts/$release_commit.json"
          EOF
          chmod +x "$out/bin/aos-system-image-e2e-fixture"
        '';
      }
    ];
  }
