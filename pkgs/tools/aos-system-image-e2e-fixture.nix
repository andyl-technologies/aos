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
  sbsigntools,
  secure-boot-test-keys,
  systemd,
  zstd,
}: let
  ukiImage = mkDerivation {
    pname = "aos-hub-e2e-uki";
    version = "2026.3.0";
    src = null;
    buildDeps = [coreutils sbsigntools secure-boot-test-keys systemd systemd.tools];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out"
          printf 'NAME=AOS Hub fixture\nID=aos-hub-fixture\n' > os-release
          printf 'quiet' > cmdline
          ${systemd.tools}/bin/ukify build \
            --stub='${systemd}/lib/systemd/boot/efi/linuxx64.efi.stub' \
            --linux='${systemd}/lib/systemd/boot/efi/systemd-bootx64.efi' \
            --uname=2026.3.0 \
            --cmdline=@cmdline \
            --os-release=@os-release \
            --signtool=sbsign \
            --secureboot-private-key='${secure-boot-test-keys}/db.key' \
            --secureboot-certificate='${secure-boot-test-keys}/db.crt' \
            --output="$out/systemd-bootx64.efi"
        '';
      }
    ];
  };
  rawImage = mkDerivation {
    pname = "aos-hub-e2e-image-raw";
    version = "2026.3.0";
    src = null;
    buildDeps = [coreutils dosfstools gptfdisk jq mtools ukiImage zstd];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out"
          filename=aos-e2e.img.zst
          truncate -s 64M image.raw
          ${gptfdisk}/sbin/sgdisk \
            --new=1:2048:71679 --typecode=1:ef00 --change-name=1:esp \
            --new=2:71680:129023 --typecode=2:8304 --change-name=2:root-a \
            image.raw
          truncate -s 34M esp.fat
          ${dosfstools}/sbin/mkfs.fat esp.fat
          ${mtools}/bin/mmd -i esp.fat ::/EFI ::/EFI/Linux ::/EFI/systemd
          ${mtools}/bin/mcopy -i esp.fat \
            '${ukiImage}/systemd-bootx64.efi' \
            ::/EFI/Linux/systemd-bootx64.efi
          ${mtools}/bin/mcopy -i esp.fat \
            '${ukiImage}/systemd-bootx64.efi' \
            ::/EFI/systemd/systemd-bootx64.efi
          dd if=esp.fat of=image.raw bs=512 seek=2048 conv=notrunc 2>/dev/null
          logical_sha256=$(sha256sum image.raw | cut -d ' ' -f1)
          rootfs_sha256=$(dd if=image.raw bs=512 skip=71680 count=57344 2>/dev/null | sha256sum | cut -d ' ' -f1)
          zstd -19 -T1 --no-progress image.raw -o "$out/$filename"
          image_sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
          image_size=$(stat -c %s "$out/$filename")
          uki='${ukiImage}/systemd-bootx64.efi'
          uki_sha256=$(sha256sum "$uki" | cut -d ' ' -f1)
          uki_size=$(stat -c %s "$uki")
          ${jq}/bin/jq -S -n \
            --arg format raw \
            --arg filename "$filename" \
            --arg sha256 "$image_sha256" \
            --arg mediaType application/vnd.aos.disk-image.raw+zstd \
            --arg logicalDiskSha256 "$logical_sha256" \
            --arg rootfsSha256 "$rootfs_sha256" \
            --arg ukiSha256 "$uki_sha256" \
            --argjson byteSize "$image_size" \
            --argjson ukiSize "$uki_size" \
            --argjson targets '["bare-metal"]' \
            '{schemaVersion: 2, name: "aos-system", version: "2026.3.0",
              architecture: "x86_64", platform: "x86_64-linux",
              format: $format, filename: $filename,
              mediaType: $mediaType, compression: "zstd", byteSize: $byteSize,
              virtualSizeBytes: 67108864, sha256: $sha256,
              logicalDiskSha256: $logicalDiskSha256,
              rootfsSha256: $rootfsSha256,
              compatibleTargets: $targets, partitionTable: "gpt",
              artifactBudgetsMiB: {root: 28, verity: 1, initrd: 1, uki: 1, esp: 34, runtimeClosure: 1, download: 64},
              kernelParams: "",
              partitions: [
                {number: 1, label: "esp", type: "esp", filesystem: "vfat",
                  sizeMiB: 34, offsetBytes: 1048576, sizeBytes: 35651584},
                {number: 2, label: "root-a", type: "root", filesystem: "fake",
                  sizeMiB: 28, offsetBytes: 36700160, sizeBytes: 29360128}],
              esp: {uki: "EFI/Linux/systemd-bootx64.efi",
                sdBoot: "EFI/systemd/systemd-bootx64.efi"},
              uki: {filename: "systemd-bootx64.efi",
                espPath: "EFI/Linux/systemd-bootx64.efi",
                byteSize: $ukiSize, sha256: $ukiSha256,
                signed: true, measured: false}}' > "$out/image-info.json"
        '';
      }
    ];
  };
  qcow2Image = mkDerivation {
    pname = "aos-hub-e2e-image-qcow2";
    version = "2026.3.0";
    src = null;
    buildDeps = [coreutils jq qemu rawImage ukiImage zstd];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out"
          filename=aos-e2e.qcow2
          zstd -d --no-progress '${rawImage}/aos-e2e.img.zst' -o image.raw
          ${qemu}/bin/qemu-img convert -f raw -O qcow2 image.raw "$out/$filename"
          image_sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
          image_size=$(stat -c %s "$out/$filename")
          logical_sha256=$(sha256sum image.raw | cut -d ' ' -f1)
          rootfs_sha256=$(dd if=image.raw bs=512 skip=71680 count=57344 2>/dev/null | sha256sum | cut -d ' ' -f1)
          uki='${ukiImage}/systemd-bootx64.efi'
          uki_sha256=$(sha256sum "$uki" | cut -d ' ' -f1)
          uki_size=$(stat -c %s "$uki")
          ${jq}/bin/jq -S -n \
            --arg filename "$filename" --arg sha256 "$image_sha256" \
            --arg logicalDiskSha256 "$logical_sha256" \
            --arg rootfsSha256 "$rootfs_sha256" \
            --arg ukiSha256 "$uki_sha256" --argjson byteSize "$image_size" \
            --argjson ukiSize "$uki_size" \
            '{schemaVersion: 2, name: "aos-system", version: "2026.3.0",
              architecture: "x86_64", platform: "x86_64-linux", format: "qcow2",
              filename: $filename,
              mediaType: "application/vnd.aos.disk-image.qcow2", compression: "none",
              byteSize: $byteSize, virtualSizeBytes: 67108864, sha256: $sha256,
              logicalDiskSha256: $logicalDiskSha256, rootfsSha256: $rootfsSha256,
              compatibleTargets: ["qemu-kvm", "openstack"], partitionTable: "gpt",
              artifactBudgetsMiB: {root: 28, verity: 1, initrd: 1, uki: 1, esp: 34, runtimeClosure: 1, download: 64},
              kernelParams: "", partitions: [
                {number: 1, label: "esp", type: "esp", filesystem: "vfat",
                  sizeMiB: 34, offsetBytes: 1048576, sizeBytes: 35651584},
                {number: 2, label: "root-a", type: "root", filesystem: "fake",
                  sizeMiB: 28, offsetBytes: 36700160, sizeBytes: 29360128}],
              esp: {uki: "EFI/Linux/systemd-bootx64.efi",
                sdBoot: "EFI/systemd/systemd-bootx64.efi"},
              uki: {filename: "systemd-bootx64.efi",
                espPath: "EFI/Linux/systemd-bootx64.efi", byteSize: $ukiSize,
                sha256: $ukiSha256, signed: true, measured: false}}' > "$out/image-info.json"
        '';
      }
    ];
  };
  projectImageFile = {
    image,
    filename,
    pname,
  }:
    mkDerivation {
      inherit pname;
      version = "2026.3.0";
      src = null;
      buildDeps = [coreutils image];
      phases = [
        {
          name = "install";
          script = ''
            rmdir "$out"
            cp '${image}/${filename}' "$out"
          '';
        }
      ];
    };
  rawImageDisk = projectImageFile {
    image = rawImage;
    filename = "aos-e2e.img.zst";
    pname = "aos-hub-e2e-image-raw-disk";
  };
  rawImageInfo = projectImageFile {
    image = rawImage;
    filename = "image-info.json";
    pname = "aos-hub-e2e-image-raw-info";
  };
  qcow2ImageDisk = projectImageFile {
    image = qcow2Image;
    filename = "aos-e2e.qcow2";
    pname = "aos-hub-e2e-image-qcow2-disk";
  };
  qcow2ImageInfo = projectImageFile {
    image = qcow2Image;
    filename = "image-info.json";
    pname = "aos-hub-e2e-image-qcow2-info";
  };
  sysroot = mkDerivation {
    pname = "aos-hub-e2e-sysroot";
    version = "2026.3.0";
    src = null;
    buildDeps = [coreutils];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/etc"
          printf 'NAME=AOS Hub producer fixture\nVERSION=2026.3.0\n' > "$out/etc/aos-release"
        '';
      }
    ];
  };
in
  mkDerivation {
    pname = "aos-system-image-e2e-fixture";
    version = "0.1.0";
    src = null;
    runtimeDeps = [
      aos
      bash
      coreutils
      git
      rawImage
      rawImageDisk
      rawImageInfo
      qcow2Image
      qcow2ImageDisk
      qcow2ImageInfo
      sysroot
      ukiImage
    ];
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
          ${aos}/bin/apr release 2026.3.0 \
            --registry image-e2e \
            --store-path '${sysroot}' \
            --source-drv '${sysroot}' \
            --name aos-system \
            --platform x86_64-linux \
            --description 'AOS Hub producer-driven system-image fixture' \
            --license MIT \
            --maintainer image-e2e@aos.invalid \
            --sysroot \
            --image-payload '${rawImage}' \
            --image-disk '${rawImageDisk}' \
            --image-info '${rawImageInfo}' \
            --image-format raw \
            --image-uki '${ukiImage}/systemd-bootx64.efi' \
            --image-payload '${qcow2Image}' \
            --image-disk '${qcow2ImageDisk}' \
            --image-info '${qcow2ImageInfo}' \
            --image-format qcow2 \
            --image-uki '${ukiImage}/systemd-bootx64.efi' \
            --channel stable \
            --init-channel \
            --key "$key" \
            --cache-url http://127.0.0.1:8799/flat-cache \
            --upload-url "file://$destination/surface"
          printf '%s\n' "$public_key" > "$destination/trust-key"
          printf '%s\n' '${rawImage}/aos-e2e.img.zst' > "$destination/raw-path"
          printf '%s\n' '${qcow2Image}/aos-e2e.qcow2' > "$destination/qcow2-path"
          test -s "$destination/surface/info/refs"
          test -s "$destination/surface/HEAD"
          EOF
          chmod +x "$out/bin/aos-system-image-e2e-fixture"
        '';
      }
    ];
    meta = {
      description = "End-to-end system image publication fixture";
      license = "Apache-2.0";
    };
  }
