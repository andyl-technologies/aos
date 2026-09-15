##! aos-boot-storage - EFI System Partition and initrd ZFS helpers
{
  bash,
  coreutils,
  jq,
  mkDerivation,
  perl,
  rsync,
  util-linux,
}: let
  version = "0.1.0";
in
  mkDerivation {
    pname = "aos-boot-storage";
    inherit version;
    src = null;

    buildDeps = [coreutils perl];
    runtimeDeps = [
      bash
      coreutils
      jq
      rsync
      util-linux
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"

          cp ${./_aos-boot-storage/mount-esp.sh.in} "$out/bin/aos-mount-esp"
          substituteInPlace "$out/bin/aos-mount-esp" \
            --replace-fail '@bash@' '${bash}/bin/bash' \
            --replace-fail '@coreutils@' '${coreutils}' \
            --replace-fail '@jq@' '${jq}' \
            --replace-fail '@util_linux@' '${util-linux}'

          cp ${./_aos-boot-storage/sync-esps.sh.in} "$out/bin/aos-sync-esps"
          substituteInPlace "$out/bin/aos-sync-esps" \
            --replace-fail '@bash@' '${bash}/bin/bash' \
            --replace-fail '@coreutils@' '${coreutils}' \
            --replace-fail '@jq@' '${jq}' \
            --replace-fail '@rsync@' '${rsync}' \
            --replace-fail '@util_linux@' '${util-linux}'

          cp ${./_aos-boot-storage/zfs-unlock.sh.in} "$out/bin/aos-zfs-unlock"
          substituteInPlace "$out/bin/aos-zfs-unlock" \
            --replace-fail '@bash@' '${bash}/bin/bash'

          ${bash}/bin/bash -n "$out/bin/aos-mount-esp"
          ${bash}/bin/bash -n "$out/bin/aos-sync-esps"
          ${bash}/bin/bash -n "$out/bin/aos-zfs-unlock"
          chmod 0755 "$out/bin/"*
        '';
      }
    ];

    meta = {
      description = "Boot-storage mount, replication, and unlock helpers";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-mount-esp";
    };
  }
