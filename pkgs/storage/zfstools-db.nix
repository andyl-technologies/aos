##! Optional database clients for the source-built ZFS snapshot tools.
{
  lib,
  mkDerivation,
  bash,
  zfstools,
  mariadb,
  postgresql,
}: let
  databaseRuntimePath = "${mariadb}/bin:${postgresql}/bin";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "zfstools-db";
    version = zfstools.version;
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A request for the database-enabled snapshot command's usage.";
        operation = "Invoke the companion wrapper without accessing a pool or database.";
        expected = "The wrapper reaches the source-built ZFS snapshot command.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/zfs-auto-snapshot"];
            exit_code = 0;
          }
        ];
      };
      badInput = {
        input = "An unsupported snapshot option.";
        operation = "Pass the option through the database-enabled wrapper.";
        expected = "The snapshot command rejects the option.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/zfs-auto-snapshot" "--qualification-invalid"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
      };
    };

    src = null;
    buildDeps = [];
    runtimeDeps = [bash zfstools mariadb postgresql];
    propagatedDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          for script in zfs-auto-snapshot zfs-cleanup-snapshots zfs-snapshot-mysql; do
            cat > "$out/bin/$script" <<EOF
          #!${bash}/bin/bash
          export PATH='${databaseRuntimePath}':\$PATH
          exec "${zfstools}/bin/$script" "\$@"
          EOF
            chmod 0755 "$out/bin/$script"
          done
        '';
      }
    ];

    meta = {
      description = "Database-aware wrappers for ZFS snapshot tools";
      homepage = "https://github.com/bdrewery/zfstools";
      license = "BSD-2-Clause";
      mainProgram = "zfs-auto-snapshot";
    };
  }
