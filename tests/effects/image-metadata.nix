##! Exercises the canonical build serializer with actual signed file artifacts.
##! The PE fixture tests metadata production; it does not claim boot readiness.
{pkgs}:
pkgs.mkDerivation {
  pname = "native-image-metadata-check";
  version = "0";
  src = null;
  buildDeps = [pkgs.aos pkgs.coreutils pkgs.util-linux pkgs.dosfstools pkgs.mtools pkgs.systemd pkgs.erofs-utils pkgs.cryptsetup pkgs.openssl pkgs.sbsigntools pkgs.jq pkgs.zstd];
  phases = [
    {
      name = "check";
      script = ''
        set -eu
        mkdir -p "$out" tree
        printf '%s\n' 'actual source-built filesystem fixture' > tree/identity
        ${pkgs.erofs-utils}/bin/mkfs.erofs root.img tree
        ${pkgs.cryptsetup}/sbin/veritysetup format root.img root.verity --root-hash-file root.roothash
        ${pkgs.cryptsetup}/sbin/veritysetup verify root.img root.verity "$(cat root.roothash)"
        truncate -s 12M image.raw
        ${pkgs.util-linux}/sbin/sfdisk image.raw <<'TABLE'
        label: gpt
        unit: sectors
        start=2048,size=2048,type=U,name=ESP
        start=4096,size=2048,type=L,name=root-a
        start=6144,size=2048,type=L,name=root-a-hash
        start=8192,size=2048,type=L,name=root-b
        start=10240,size=2048,type=L,name=root-b-hash
        TABLE
        dd if=root.img of=image.raw bs=512 seek=4096 conv=notrunc status=none
        dd if=root.verity of=image.raw bs=512 seek=6144 conv=notrunc status=none
        ${pkgs.util-linux}/sbin/sfdisk --json image.raw > table.json
        ${pkgs.openssl}/bin/openssl req -new -x509 -newkey rsa:2048 -nodes \
          -subj /CN=AOS-metadata-protocol-fixture -keyout key.pem -out cert.pem -days 1
        ${pkgs.sbsigntools}/bin/sbsign --key key.pem --cert cert.pem \
          --output uki-a.efi ${pkgs.systemd}/lib/systemd/boot/efi/linuxx64.efi.stub
        cp uki-a.efi uki-b.efi
        ${pkgs.sbsigntools}/bin/sbverify --cert cert.pem uki-a.efi
        ${pkgs.sbsigntools}/bin/sbverify --cert cert.pem uki-b.efi
        cp uki-a.efi systemd-boot.efi
        truncate -s 1M esp.img
        ${pkgs.dosfstools}/sbin/mkfs.vfat esp.img
        ${pkgs.mtools}/bin/mcopy -i esp.img uki-a.efi ::normal-a.efi
        dd if=esp.img of=image.raw bs=512 seek=2048 conv=notrunc status=none
        fat_id=$(${pkgs.util-linux}/sbin/blkid -p -s UUID -o value esp.img)
        ${pkgs.zstd}/bin/zstd -q image.raw -o disk.zst
        ${pkgs.jq}/bin/jq -n --arg fat "$fat_id" '{version:"metadata-fixture",system_variant:"protocol-fixture",
          platform:"x86_64-linux",root_filesystem:"root.img",verity_tree:"root.verity",
          root_hash:"root.roothash",normal_a:{artifact:"uki-a.efi",measurement:null,measurement_signature:null},
          normal_b:{artifact:"uki-b.efi",measurement:null,measurement_signature:null},
          recovery_a:null,recovery_b:null,bootloader:"systemd-boot.efi",logical_disk:"image.raw",
          partition_table:"table.json",fat_volume_id:$fat,
          raw_format:"disk.zst",raw_filename:"disk.zst",secure_boot_certificate:"cert.pem"}' > input.json
        ${pkgs.aos}/bin/aos-image-metadata "$out/image-info.json" < input.json
        root_digest="sha256:$(sha256sum root.img | cut -d ' ' -f1)"
        disk_digest="sha256:$(sha256sum image.raw | cut -d ' ' -f1)"
        uki_digest="sha256:$(sha256sum uki-b.efi | cut -d ' ' -f1)"
        ${pkgs.jq}/bin/jq -e --arg root "$root_digest" --arg disk "$disk_digest" --arg uki "$uki_digest" \
          '.schema_version == "aos.image.metadata/v1" and .root.filesystem_sha256 == $root
            and .disk.logical.sha256 == $disk and .efi.normal_b.artifact.sha256 == $uki
            and .efi.normal_b.artifact.path == "uki-b.efi" and .disk.layout.root_a_start == 4096
            and (has("assembly_digest") | not) and (has("capabilities") | not)
            and (has("schemaVersion") | not)' "$out/image-info.json"
        printf 'changed\n' >> root.img
        if ${pkgs.aos}/bin/aos-image-metadata rejected.json < input.json; then
          echo 'serializer accepted filesystem bytes outside the committed partition' >&2
          exit 1
        fi
      '';
    }
  ];
}
