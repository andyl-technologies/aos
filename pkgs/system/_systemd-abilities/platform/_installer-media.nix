##! Assembles bootable AOS installer media around a signed release image.
##!
##! The media is a raw GPT disk for writing to a USB stick:
##!
##!   1. `aos-installer-esp` (ESP type, FAT32): the signed installer UKI as the
##!      removable-media fallback loader. The partition is deliberately not
##!      labeled `ESP`, so it never collides with the installed disk's ESP.
##!   2. `aos-payload` (ext4, read-only at runtime): the release's compressed
##!      raw disk, its image metadata, and a db-signed manifest over them.
##!   3. `aos-meta` (FAT32, filesystem label `AOS-META`): the operator's
##!      `host.nix`. FAT keeps it editable from any workstation.
##!
##! The installer UKI boots the image's own kernel with an initrd evaluated in
##! installer mode. It carries no root hash and no PCR policy: it never
##! mounts an immutable root and must not unseal installed-system state.
{
  pkgs,
  lib,
  config,
  kernel,
  name,
  targetPlatform,
  releaseImage,
  hostConfiguration,
}: let
  version = config.aos.system.version;
  sb = config.aos.boot.secureBoot;
  efiFallback =
    {
      "x86_64" = "BOOTX64.EFI";
      "aarch64" = "BOOTAA64.EFI";
    }
    .${
      targetPlatform.constraints.cpu
    };
  diskFilename = "aos-${name}.img.zst";
  mediaFilename = "aos-${name}-installer.img";

  # Keep only console and diagnostics parameters. Root, verity, and LUKS
  # selection describe an installed system and have no meaning on the media.
  cmdline = lib.concatStringsSep " " (
    builtins.filter
    (parameter: builtins.any (prefix: lib.hasPrefix prefix parameter) [
      "console="
      "net.ifnames="
      "systemd.journald.forward_to_console="
      "loglevel="
      "lockdown="
      "module.sig_enforce="
    ])
    config.aos.boot.kernelParams
    ++ ["rd.systemd.unit=aos-installer.target" "rd.luks=0"]
  );

  osRelease = pkgs.writeTextFile {
    name = "aos-installer-os-release";
    destination = "/os-release";
    text = ''
      NAME="AOS Installer"
      ID=aos-installer
      VERSION="${version}"
      VERSION_ID="${version}"
      PRETTY_NAME="AOS Installer (${version})"
      AOS_RELEASE_ID="${version}"
      AOS_PLATFORM="${targetPlatform.system}"
    '';
  };

  installerUki = pkgs.aos-uki {
    name = "${name}-installer";
    inherit version cmdline;
    kernel = kernel.package;
    initrd = config.system.build.initrd;
    osRelease = "${osRelease}/os-release";
    secureBootKey = sb.dbKey;
    secureBootCert = sb._effectiveDbCert;
    pcrPrivateKey = null;
    pcrPublicKey = null;
    rootHashFile = null;
  };
in
  pkgs.mkDerivation {
    pname = "aos-installer-media-${name}";
    inherit version;
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.dosfstools
      pkgs.e2fsprogs
      pkgs.jq
      pkgs.mtools
      pkgs.openssl
      pkgs.util-linux
    ];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "build-media";
        script = ''
          set -eu
          export MTOOLS_SKIP_CHECK=1

          echo "==> Staging the signed release payload"
          mkdir payload
          cp -L ${releaseImage}/${diskFilename} payload/${diskFilename}
          cp -L ${releaseImage}/image-info.json payload/image-info.json
          cp -L ${releaseImage}/image-delivery.json payload/image-delivery.json
          component() {
            jq -n --arg id "$1" --arg path "$2" \
              --argjson size "$(stat -c %s "payload/$2")" \
              --arg sha256 "$(sha256sum "payload/$2" | cut -d' ' -f1)" \
              '{id:$id, path:$path, byte_size:$size, sha256:$sha256}'
          }
          {
            component disk-image ${diskFilename}
            component image-info image-info.json
            component image-delivery image-delivery.json
          } | jq -s -S \
            --slurpfile delivery payload/image-delivery.json \
            '{schema:"aos.installer-payload/v1",
              release:$delivery[0].version,
              architecture:$delivery[0].architecture,
              platform:$delivery[0].platform,
              disk:{byte_size:$delivery[0].virtualSizeBytes,
                    sha256:$delivery[0].logicalDiskSha256},
              components:.}' > payload/installer-payload.json
          openssl dgst -sha256 -sign ${toString sb.dbKey} \
            -out payload/installer-payload.json.sig payload/installer-payload.json
          openssl x509 -pubkey -noout -in ${sb._effectiveDbCert} > db.pub
          openssl dgst -sha256 -verify db.pub \
            -signature payload/installer-payload.json.sig payload/installer-payload.json

          echo "==> Creating the payload filesystem"
          payload_bytes=$(du -sb payload | cut -f1)
          payload_mib=$(( (payload_bytes * 105 / 100) / 1048576 + 64 ))
          truncate -s "''${payload_mib}M" payload.img
          mkfs.ext4 -q -F -L aos-payload -E root_owner=0:0 -d payload payload.img

          echo "==> Creating the installer ESP"
          uki=${installerUki}/aos-${name}-installer-${version}.efi
          uki_bytes=$(stat -c %s "$uki")
          esp_mib=$(( uki_bytes / 1048576 + 48 ))
          if [ "$esp_mib" -lt 64 ]; then esp_mib=64; fi
          truncate -s "''${esp_mib}M" esp.img
          mkfs.vfat -F 32 -n AOS-BOOT esp.img
          mmd -i esp.img ::/EFI ::/EFI/BOOT
          mcopy -i esp.img "$uki" ::/EFI/BOOT/${efiFallback}

          echo "==> Creating the AOS-META partition"
          meta_mib=64
          truncate -s "''${meta_mib}M" meta.img
          mkfs.vfat -F 32 -n AOS-META meta.img
          ${lib.optionalString (hostConfiguration != null) ''
            mcopy -i meta.img ${hostConfiguration} ::/host.nix
          ''}

          echo "==> Assembling the GPT media image"
          esp_start=2048
          esp_sectors=$(( esp_mib * 2048 ))
          payload_start=$(( esp_start + esp_sectors ))
          payload_sectors=$(( payload_mib * 2048 ))
          meta_start=$(( payload_start + payload_sectors ))
          meta_sectors=$(( meta_mib * 2048 ))
          disk_sectors=$(( meta_start + meta_sectors + 2048 ))
          truncate -s $(( disk_sectors * 512 )) media.img
          sfdisk --quiet media.img <<PTABLE
          label: gpt
          start=$esp_start, size=$esp_sectors, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="aos-installer-esp"
          start=$payload_start, size=$payload_sectors, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="aos-payload"
          start=$meta_start, size=$meta_sectors, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, name="aos-meta"
          PTABLE
          dd if=esp.img of=media.img bs=512 seek=$esp_start conv=notrunc status=none
          dd if=payload.img of=media.img bs=512 seek=$payload_start conv=notrunc status=none
          dd if=meta.img of=media.img bs=512 seek=$meta_start conv=notrunc status=none
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out
          mv media.img $out/${mediaFilename}
          cp payload/installer-payload.json $out/installer-payload.json
          ln -s ${installerUki}/aos-${name}-installer-${version}.efi $out/installer.efi
        '';
      }
    ];
  }
