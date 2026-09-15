##! aos-boot-storage - EFI System Partition and initrd ZFS helpers
{
  bash,
  coreutils,
  jq,
  lib,
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

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The installed boot-storage helper package.";
        operation = "Verify every package-owned helper is executable.";
        expected = "All three boot-storage entry points are regular executable files.";
        files = {};
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import os

                paths = [
                    "@out@/bin/aos-mount-esp",
                    "@out@/bin/aos-sync-esps",
                    "@out@/bin/aos-zfs-unlock",
                ]
                assert all(os.path.isfile(path) and os.access(path, os.X_OK) for path in paths)
                print("aos-boot-storage executables passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "aos-boot-storage executables passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "An incomplete ZFS unlock invocation.";
        operation = "Invoke the unlock helper without its required storage arguments.";
        expected = "The helper rejects the incomplete invocation before touching storage.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/aos-zfs-unlock" "--aos-qualification-invalid"];
            exit_code = 2;
            stdout.exact = "";
            stderr.exact = "usage: aos-zfs-unlock POOL ENCRYPTION_ROOT SEALED_KEY_PATH ESP_COUNT ESP... EXPECTED_DEVICE...\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };

    buildDeps = [coreutils perl];
    runtimeDeps = [
      bash
      coreutils
      jq
      rsync
      util-linux
    ];
    propagatedDeps = [];
    abilities = ./_aos-boot-storage;

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
