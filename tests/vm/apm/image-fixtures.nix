# Shared production-valid system image fixtures for APM VM tests.
{pkgs}: let
  imageUki = pkgs.mkDerivation {
    pname = "apm-vm-image-uki";
    version = "2026.03";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.sbsigntools
      pkgs.secure-boot-test-keys
      pkgs.systemd
      pkgs.systemd.tools
    ];
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out"
          printf 'NAME=AOS VM image test\nID=aos-vm-image-test\n' > os-release
          printf 'quiet' > cmdline
          ${pkgs.systemd.tools}/bin/ukify build \
            --stub='${pkgs.systemd}/lib/systemd/boot/efi/linuxx64.efi.stub' \
            --linux='${pkgs.systemd}/lib/systemd/boot/efi/systemd-bootx64.efi' \
            --uname=2026.03 \
            --cmdline=@cmdline \
            --os-release=@os-release \
            --signtool=sbsign \
            --secureboot-private-key='${pkgs.secure-boot-test-keys}/db.key' \
            --secureboot-certificate='${pkgs.secure-boot-test-keys}/db.crt' \
            --output="$out/systemd-bootx64.efi"
        '';
      }
    ];
  };

  mkImage = {format}:
    pkgs.mkDerivation {
      pname = "apm-vm-image-${format}";
      version = "2026.03";
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.dosfstools
        pkgs.gptfdisk
        pkgs.jq
        pkgs.mtools
        pkgs.qemu
        pkgs.zstd
        imageUki
      ];
      UKI_STORE_PATH = "${imageUki}";
      UKI_FILENAME = "systemd-bootx64.efi";
      phases = [
        {
          name = "build";
          script = ''
            mkdir -p "$out"
            truncate -s 64M image.raw
            ${pkgs.gptfdisk}/sbin/sgdisk \
              --disk-guid=A05A05A0-0000-4000-8000-000000000001 \
              --new=1:2048:71679 --typecode=1:ef00 --change-name=1:esp \
              --partition-guid=1:A05A05A0-0000-4000-8000-000000000002 \
              --new=2:71680:129023 --typecode=2:8304 --change-name=2:root-a \
              --partition-guid=2:A05A05A0-0000-4000-8000-000000000003 \
              image.raw
            truncate -s 34M esp.fat
            ${pkgs.dosfstools}/sbin/mkfs.fat -i A05A05A0 esp.fat
            ${pkgs.mtools}/bin/mmd -i esp.fat ::/EFI ::/EFI/Linux ::/EFI/systemd
            ${pkgs.mtools}/bin/mcopy -i esp.fat \
              "$UKI_STORE_PATH/$UKI_FILENAME" \
              ::/EFI/Linux/$UKI_FILENAME
            ${pkgs.mtools}/bin/mcopy -i esp.fat \
              "$UKI_STORE_PATH/$UKI_FILENAME" \
              ::/EFI/systemd/systemd-bootx64.efi
            dd if=esp.fat of=image.raw bs=512 seek=2048 conv=notrunc 2>/dev/null
            printf 'AOSRAW\n' | dd of=image.raw bs=512 seek=71680 conv=notrunc \
              2>/dev/null
            logical_disk_sha256=$(sha256sum image.raw | cut -d ' ' -f1)
            rootfs_sha256=$(dd if=image.raw bs=512 skip=71680 count=57344 \
              2>/dev/null | sha256sum | cut -d ' ' -f1)
            ${
              if format == "raw"
              then ''
                filename=aos-test.img.zst
                zstd -19 -T1 --no-progress image.raw -o "$out/$filename"
              ''
              else if format == "qcow2"
              then ''
                filename=aos-test.qcow2
                ${pkgs.qemu}/bin/qemu-img convert -f raw -O qcow2 \
                  image.raw "$out/$filename"
              ''
              else ''
                filename="aos-test.${format}"
                printf 'AOS image ${format}\n' > "$out/$filename"
                logical_disk_sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
              ''
            }
            image_sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
            image_size=$(stat -c %s "$out/$filename")
            uki_path="$UKI_STORE_PATH/$UKI_FILENAME"
            uki_sha256=$(sha256sum "$uki_path" | cut -d ' ' -f1)
            uki_size=$(stat -c %s "$uki_path")
            ${pkgs.jq}/bin/jq -S -n \
              --arg format '${format}' \
              --arg filename "$filename" \
              --arg sha256 "$image_sha256" \
              --arg logicalDiskSha256 "$logical_disk_sha256" \
              --arg rootfsSha256 "$rootfs_sha256" \
              --arg mediaType '${
              if format == "raw"
              then "application/vnd.aos.disk-image.raw+zstd"
              else "application/vnd.aos.disk-image.qcow2"
            }' \
              --arg ukiFilename "$UKI_FILENAME" \
              --arg ukiEspPath "EFI/Linux/$UKI_FILENAME" \
              --arg ukiSha256 "$uki_sha256" \
              --argjson byteSize "$image_size" \
              --argjson ukiSize "$uki_size" \
              --argjson targets '${
              if format == "raw"
              then ''["bare-metal"]''
              else ''["qemu-kvm","openstack"]''
            }' \
              '{schemaVersion: 2, name: "server", version: "2026.03",
                architecture: "x86_64", platform: "x86_64-linux",
                format: $format, filename: $filename,
                mediaType: $mediaType, compression: "${
              if format == "raw"
              then "zstd"
              else "none"
            }", byteSize: $byteSize,
                virtualSizeBytes: 67108864,
                sha256: $sha256, logicalDiskSha256: $logicalDiskSha256,
                rootfsSha256: $rootfsSha256, compatibleTargets: $targets,
                artifactBudgetsMiB: {root: 28, verity: 1, initrd: 1, uki: 1, esp: 34, runtimeClosure: 1, download: 64},
                partitionTable: "gpt", kernelParams: "",
                partitions: [
                  {number: 1, label: "esp", type: "esp", filesystem: "vfat",
                    sizeMiB: 34, offsetBytes: 1048576, sizeBytes: 35651584},
                  {number: 2, label: "root-a", type: "root", filesystem: "fake",
                    sizeMiB: 28, offsetBytes: 36700160, sizeBytes: 29360128}],
                esp: {uki: $ukiEspPath, sdBoot: "EFI/systemd/systemd-bootx64.efi"},
                uki: {filename: $ukiFilename, espPath: $ukiEspPath,
                  byteSize: $ukiSize, sha256: $ukiSha256, signed: true, measured: false}}' \
              > "$out/image-info.json"
          '';
        }
      ];
    };

  projectImageFile = {
    image,
    filename,
    pname,
  }:
    pkgs.mkDerivation {
      inherit pname;
      version = "2026.03";
      src = null;
      buildDeps = [pkgs.coreutils image];
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

  imageRaw = mkImage {format = "raw";};
  imageQcow2 = mkImage {format = "qcow2";};
  imageRawDisk = projectImageFile {
    image = imageRaw;
    filename = "aos-test.img.zst";
    pname = "apm-vm-image-raw-disk";
  };
  imageRawInfo = projectImageFile {
    image = imageRaw;
    filename = "image-info.json";
    pname = "apm-vm-image-raw-info";
  };
  imageQcow2Disk = projectImageFile {
    image = imageQcow2;
    filename = "aos-test.qcow2";
    pname = "apm-vm-image-qcow2-disk";
  };
  imageQcow2Info = projectImageFile {
    image = imageQcow2;
    filename = "image-info.json";
    pname = "apm-vm-image-qcow2-info";
  };
in {
  inherit
    imageQcow2
    imageQcow2Disk
    imageQcow2Info
    imageRaw
    imageRawDisk
    imageRawInfo
    imageUki
    ;
}
