##! Dedicated signed-recovery initrd builder
##!
##! This sibling of `_initrd-builder.nix` deliberately owns a smaller static
##! unit graph and executable set. It never imports normal initrd units or
##! generators, so normal root mounting, switch-root, provisioning, metadata,
##! activation, package installation, TPM unlock, debug gettys, and automatic
##! networking cannot be pulled into recovery by target ordering changes.
{
  pkgs,
  lib,
  kernel,
  loadModules,
  dbCert,
  authorizedDbCerts,
  slotManifest,
  recoveryCopy,
  recoveryAbi,
  platform,
  moduleAbi,
}: let
  inherit
    (pkgs)
    aos-recovery
    bash
    binutils
    coreutils
    cpio
    cryptsetup
    findutils
    jq
    kmod
    openssl
    sbsigntools
    systemd
    util-linux
    zstd
    ;

  recoveryPackages = [
    aos-recovery
    bash
    binutils
    coreutils
    cryptsetup
    jq
    kmod
    openssl
    sbsigntools
    systemd
    util-linux
  ];

  modulesLoadConf = lib.concatStringsSep "\n" loadModules;
  copy =
    if builtins.elem recoveryCopy ["A" "B"]
    then recoveryCopy
    else throw "recoveryCopy must be A or B";

  upstreamUnits = [
    "basic.target"
    "paths.target"
    "poweroff.target"
    "reboot.target"
    "shutdown.target"
    "slices.target"
    "sockets.target"
    "sysinit.target"
    "systemd-ask-password-console.path"
    "systemd-ask-password-console.service"
    "systemd-journald-dev-log.socket"
    "systemd-journald.service"
    "systemd-journald.socket"
    "systemd-modules-load.service"
    "systemd-poweroff.service"
    "systemd-reboot.service"
    "systemd-tmpfiles-setup-dev.service"
    "systemd-tmpfiles-setup.service"
    "systemd-udev-trigger.service"
    "systemd-udevd-control.socket"
    "systemd-udevd-kernel.socket"
    "systemd-udevd.service"
  ];

  unitSymlinks =
    lib.concatMapStringsSep "\n" (unit: ''
      test -e ${systemd}/lib/systemd/system/${unit} || {
        echo "recovery-initrd: missing upstream unit ${unit}" >&2
        exit 1
      }
      ln -s ${systemd}/lib/systemd/system/${unit} root/lib/systemd/system/${unit}
    '')
    upstreamUnits;
in
  pkgs.mkDerivation {
    pname = "aos-recovery-initrd";
    version = "1";
    src = null;

    buildDeps = [cpio zstd coreutils findutils];
    runtimeDeps = [];
    propagatedDeps = [];

    exportReferencesGraph = lib.concatLists (
      lib.imap (index: package: ["closure-${toString index}" package]) recoveryPackages
    );

    phases = [
      {
        name = "build";
        script = ''
          set -euo pipefail

          grep -h '^/nix/store/' closure-* | sort -u > closure-paths
          mkdir -p \
            root/bin root/dev root/etc/aos/trust root/etc/modules-load.d root/etc/systemd/system \
            root/lib/modules root/lib/systemd/system root/lib/udev/rules.d \
            root/lib/aos/recovery \
            root/nix/store root/proc root/root root/run root/sbin root/sys \
            root/sys/firmware/efi/efivars root/tmp root/var
          chmod 0700 root/root
          ln -s . root/usr

          while IFS= read -r path; do
            cp -a "$path" "root$path"
          done < closure-paths
          chmod -R u+w root/nix/store

          ln -s ${systemd}/lib/systemd/systemd root/init
          ln -s ${systemd}/lib/systemd/systemd root/sbin/init
          ln -s ${aos-recovery}/bin/aos-recovery root/bin/aos-recovery
          ln -s ${bash}/bin/bash root/bin/bash
          ln -s bash root/bin/sh
          ln -s ${systemd}/bin/systemctl root/bin/systemctl
          ln -s ${systemd}/bin/bootctl root/bin/bootctl
          ln -s ${systemd}/bin/systemd-ask-password root/bin/systemd-ask-password
          ln -s ${systemd}/bin/udevadm root/bin/udevadm
          ln -s ${binutils}/bin/objcopy root/bin/objcopy
          ln -s ${coreutils}/bin/sync root/bin/sync
          ln -s ${jq}/bin/jq root/bin/jq
          ln -s ${openssl}/bin/openssl root/bin/openssl
          ln -s ${sbsigntools}/bin/sbverify root/bin/sbverify
          ln -s ${util-linux}/bin/lsblk root/bin/lsblk
          ln -s ${util-linux}/bin/mount root/bin/mount
          ln -s ${util-linux}/bin/umount root/bin/umount
          ln -s ${util-linux}/sbin/blkid root/bin/blkid
          ln -s ${cryptsetup}/sbin/cryptsetup root/bin/cryptsetup
          ln -s ${cryptsetup}/sbin/veritysetup root/bin/veritysetup

          if [ ! -d ${kernel}/lib/modules ]; then
            echo "recovery-initrd: kernel module tree is missing" >&2
            exit 1
          fi
          cp -a ${kernel}/lib/modules/. root/lib/modules/

          for rules_dir in root/nix/store/*/lib/udev/rules.d; do
            [ -d "$rules_dir" ] || continue
            for rule in "$rules_dir"/*.rules; do
              [ -e "$rule" ] || continue
              name=$(basename "$rule")
              target="/''${rule#root/}"
              if [ ! -e "root/lib/udev/rules.d/$name" ]; then
                ln -s "$target" "root/lib/udev/rules.d/$name"
              fi
            done
          done

          cat > root/etc/modules-load.d/recovery.conf <<'MODULES'
          ${modulesLoadConf}
          MODULES
          cp ${dbCert} root/etc/aos/trust/db.crt
          cp ${authorizedDbCerts} root/etc/aos/trust/authorized-db-certs.pem
          cp ${slotManifest}/slot-manifest.json root/lib/aos/recovery/slot-manifest.json
          cp ${slotManifest}/slot-manifest.json.sig root/lib/aos/recovery/slot-manifest.json.sig
          cat > root/etc/os-release <<'OS_RELEASE'
          NAME="AOS"
          ID=aos
          PRETTY_NAME="ANDYL OS signed recovery"
          AOS_RECOVERY_COPY=${copy}
          AOS_RECOVERY_ABI=${toString recoveryAbi}
          AOS_PLATFORM=${platform}
          AOS_MODULE_ABI=${toString moduleAbi}
          OS_RELEASE
          cp root/etc/os-release root/etc/initrd-release
          cat > root/etc/passwd <<'PASSWD'
          root:x:0:0:root:/root:/bin/bash
          nobody:x:65534:65534:Nobody:/:/sbin/nologin
          PASSWD
          cat > root/etc/group <<'GROUP'
          root:x:0:
          tty:x:5:
          disk:x:6:
          systemd-journal:x:190:
          nobody:x:65534:
          GROUP
          cat > root/etc/shadow <<'SHADOW'
          root:!*::0:99999:7:::
          SHADOW
          chmod 0600 root/etc/shadow
          : > root/etc/machine-id

          ${unitSymlinks}

          cat > root/etc/systemd/system/aos-recovery.target <<'TARGET'
          [Unit]
          Description=AOS signed recovery environment
          DefaultDependencies=no
          Requires=systemd-journald.socket systemd-udevd.service systemd-udev-trigger.service sys-firmware-efi-efivars.mount aos-recovery-ui.service
          After=systemd-journald.socket systemd-udevd.service systemd-udev-trigger.service sys-firmware-efi-efivars.mount
          Conflicts=shutdown.target
          AllowIsolate=yes
          TARGET

          cat > root/etc/systemd/system/sys-firmware-efi-efivars.mount <<'MOUNT'
          [Unit]
          Description=Read-only EFI variable filesystem
          DefaultDependencies=no
          Before=aos-recovery-ui.service

          [Mount]
          What=efivarfs
          Where=/sys/firmware/efi/efivars
          Type=efivarfs
          Options=ro,nosuid,nodev,noexec
          MOUNT

          cat > root/etc/systemd/system/aos-recovery-ui.service <<'SERVICE'
          [Unit]
          Description=AOS bounded recovery console
          DefaultDependencies=no
          Requires=dev-console.device
          After=dev-console.device systemd-udev-trigger.service

          [Service]
          Type=simple
          ExecStartPre=-/bin/umount /var
          ExecStartPre=-/bin/cryptsetup close var
          ExecStart=/bin/aos-recovery
          ExecStopPost=-/bin/umount /var
          ExecStopPost=-/bin/cryptsetup close var
          Restart=on-failure
          RestartSec=1s
          StandardInput=tty
          StandardOutput=tty
          StandardError=tty
          TTYPath=/dev/console
          TTYReset=yes
          TTYVHangup=yes
          SERVICE

          ln -s aos-recovery.target root/etc/systemd/system/default.target

          # Remove executable boot paths that are present in the monolithic
          # systemd package but are outside the recovery contract. No unit or
          # generator directory refers to these files.
          for store_systemd in root/nix/store/*-systemd-*; do
            [ -d "$store_systemd" ] || continue
            rm -f \
              "$store_systemd/bin/homedctl" \
              "$store_systemd/bin/kernel-install" \
              "$store_systemd/bin/localectl" \
              "$store_systemd/bin/loginctl" \
              "$store_systemd/bin/machinectl" \
              "$store_systemd/bin/networkctl" \
              "$store_systemd/bin/portablectl" \
              "$store_systemd/bin/resolvectl" \
              "$store_systemd/bin/systemd-creds" \
              "$store_systemd/bin/systemd-cryptsetup" \
              "$store_systemd/bin/systemd-cryptenroll" \
              "$store_systemd/bin/systemd-repart" \
              "$store_systemd/bin/systemd-run" \
              "$store_systemd/bin/systemd-sysext" \
              "$store_systemd/bin/systemd-sysupdate" \
              "$store_systemd/bin/timedatectl" \
              "$store_systemd/lib/systemd/systemd-cryptsetup" \
              "$store_systemd/lib/systemd/systemd-networkd" \
              "$store_systemd/lib/systemd/systemd-networkd-wait-online" \
              "$store_systemd/lib/systemd/systemd-repart" \
              "$store_systemd/lib/systemd/system-generators/systemd-fstab-generator" \
              "$store_systemd/lib/systemd/system-generators/systemd-gpt-auto-generator" \
              "$store_systemd/lib/systemd/system-generators/systemd-run-generator"
            rm -rf \
              "$store_systemd/lib/systemd/network" \
              "$store_systemd/lib/systemd/system-generators" \
              "$store_systemd/lib/systemd/user-generators" \
              "$store_systemd/lib/systemd/system/debug-shell.service" \
              "$store_systemd/lib/systemd/system/emergency.service" \
              "$store_systemd/lib/systemd/system/emergency.target" \
              "$store_systemd/lib/systemd/system/getty@.service" \
              "$store_systemd/lib/systemd/system/initrd-switch-root.service" \
              "$store_systemd/lib/systemd/system/initrd-switch-root.target" \
              "$store_systemd/lib/systemd/system/rescue.service" \
              "$store_systemd/lib/systemd/system/rescue.target" \
              "$store_systemd/lib/systemd/system/serial-getty@.service" \
              "$store_systemd/lib/systemd/system/systemd-cryptsetup@.service" \
              "$store_systemd/lib/systemd/system/systemd-networkd.service" \
              "$store_systemd/lib/systemd/system/systemd-networkd.socket" \
              "$store_systemd/lib/systemd/system/systemd-networkd-wait-online.service" \
              "$store_systemd/lib/systemd/system/systemd-repart.service" \
              "$store_systemd/lib/systemd/system/systemd-repart.socket" \
              "$store_systemd/lib/systemd/system/initrd-root-fs.target.wants/systemd-repart.service" \
              "$store_systemd/lib/systemd/system/sockets.target.wants/systemd-repart.socket" \
              "$store_systemd/lib/systemd/system/sysinit.target.wants/systemd-repart.service"
          done
          for store_util_linux in root/nix/store/*-util-linux-*; do
            [ -d "$store_util_linux" ] || continue
            rm -f \
              "$store_util_linux/bin/agetty" \
              "$store_util_linux/sbin/agetty" \
              "$store_util_linux/sbin/sulogin"
          done

          # Load-bearing archive audit: fail if a future change reintroduces a
          # normal initrd unit, generator, or executable under another path.
          forbidden=$(find root -type f -o -type l | grep -E \
            '/(aos-var-crypt|aos-repart|aos-metadata|initrd-switch-root|mount-var|systemd-networkd|systemd-repart|systemd-cryptsetup|systemd-fstab-generator|systemd-gpt-auto-generator|debug-shell|agetty|sulogin)(\.service|\.socket|\.target|$)' \
            || true)
          if [ -n "$forbidden" ]; then
            echo "recovery-initrd: forbidden recovery closure members:" >&2
            echo "$forbidden" >&2
            exit 1
          fi
          if find root -type f -o -type l \
            | grep -q '/system-generators/'; then
            echo "recovery-initrd: runtime generators are forbidden" >&2
            exit 1
          fi

          mkdir -p $out
          (
            cd root
            find . -print0 | sort -z | cpio --null -o -H newc -R +0:+0 --reproducible
          ) | zstd -19 -T1 > $out/initrd.img
        '';
      }
    ];

    meta = {
      description = "Dedicated initrd for AOS signed recovery UKIs";
    };
  }
