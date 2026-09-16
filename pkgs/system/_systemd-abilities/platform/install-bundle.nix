##! Package-owned redundant-firmware and encrypted-ZFS installer bundle.
{
  bootArtifacts,
  budgetCheck,
  config,
  image,
  lib,
  pkgs,
}: let
  storage = config.aos.boot.storage;
  zfs = config.aos.filesystems.zfs.package;
in
  pkgs.mkDerivation {
    pname = "aos-${config.aos.system.name}-zfs-installer";
    version = config.aos.system.version;
    src = null;
    buildDeps = [pkgs.coreutils pkgs.findutils budgetCheck];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/payload/esp"
          ln -s ${image.rootfs}/root.img "$out/payload/root.img"
          ln -s ${image.rootfs}/root.verity "$out/payload/root.verity"
          cp -R ${bootArtifacts.espTree}/esp/. "$out/payload/esp/"
          cp ${bootArtifacts.pcrPublicKey} "$out/payload/pcr-public.pem"
          cp ${./install-zfs.sh.in} "$out/bin/aos-install-zfs"
          substituteInPlace "$out/bin/aos-install-zfs" \
            --replace-fail '@bash@' '${pkgs.bash}/bin/bash' \
            --replace-fail '@coreutils@' '${pkgs.coreutils}' \
            --replace-fail '@dosfstools@' '${pkgs.dosfstools}' \
            --replace-fail '@gptfdisk@' '${pkgs.gptfdisk}' \
            --replace-fail '@mtools@' '${pkgs.mtools}' \
            --replace-fail '@credential_seal@' '${pkgs.systemd}/libexec/aos-boot-credential-seal' \
            --replace-fail '@util_linux@' '${pkgs.util-linux}' \
            --replace-fail '@zfs@' '${zfs}' \
            --replace-fail '@pool@' '${storage.zfs.poolName}' \
            --replace-fail '@dataset@' '${storage.zfs.dataset}' \
            --replace-fail '@compatibility@' '${storage.zfs.compatibility}' \
            --replace-fail '@sealed_key_path@' '${storage.zfs.sealedKeyPath}' \
            --replace-fail '@signed_pcrs@' '${config.aos.boot.secureBoot.measuredBoot.signedPcrs}' \
            --replace-fail '@pinned_pcrs@' '${config.aos.boot.secureBoot.measuredBoot.pinnedPcrs}' \
            --replace-fail '@esp_devices@' '${lib.concatStringsSep " " storage.espDevices}' \
            --replace-fail '@esp_count@' '${toString (builtins.length storage.espDevices)}' \
            --replace-fail '@root_slot_size@' '${toString storage.zfs.rootSlotSizeMiB}' \
            --replace-fail '@verity_slot_size@' '${toString storage.zfs.veritySlotSizeMiB}' \
            --replace-fail '@esp_size@' '${toString config.aos.image.budgets.maxFirmwarePartitionMiB}'
          ${pkgs.bash}/bin/bash -n "$out/bin/aos-install-zfs"
          chmod 0755 "$out/bin/aos-install-zfs"
        '';
      }
    ];
    meta.description = "Guarded redundant-firmware and encrypted-ZFS installer bundle";
  }
