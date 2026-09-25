##! zfstools — Scheduled ZFS snapshot management utilities
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  bash,
  ruby,
  zfs,
  coreutils,
  grep,
  mariadb,
  postgresql,
}: let
  version = "0.3.6";
  runtimePath = "${zfs}/bin:${zfs}/sbin:${coreutils}/bin";
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
    pname = "zfstools";
    outputs = ["out" "db"];
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Zfs-auto-snapshot prints its interval, retention, dry-run, pool, and UTC controls.";
        "files" = {};
        "input" = "An invocation without a snapshot interval or retention count.";
        "operation" = "Request the zfs-auto-snapshot usage contract without accessing a pool.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/zfs-auto-snapshot\"], capture_output=True, text=True)\nassert result.returncode == 0 and result.stdout.startswith(\"Usage:\") and \"INTERVAL\" in result.stdout and \"KEEP\" in result.stdout\nprint(\"zfstools operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "zfstools operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Zfs-auto-snapshot rejects the unknown option.";
        "files" = {};
        "input" = "An option outside zfs-auto-snapshot's supported switch set.";
        "operation" = "Parse the unsupported option before accessing any ZFS pool.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import sys\nimport subprocess\nresult = subprocess.run([\"@out@/bin/zfs-auto-snapshot\", \"--qualification-invalid\"], capture_output=True, text=True)\nassert result.returncode != 0 and \"unrecognized option\" in result.stderr\n\nsys.stderr.write(\"zfstools rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "zfstools rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://github.com/bdrewery/zfstools/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-BgES2J8R6VQV8HzbwF/vKaahvFBGBGxW038WsSMvss8=";
    };

    buildDeps = [];
    runtimeDeps = [ruby zfs coreutils];
    propagatedDeps = [];
    nukeRefsKeep = [bash mariadb postgresql];

    abilities = ./_zfstools;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd zfstools-${version}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/lib"
          cp -R bin/. "$out/bin/"
          cp -R lib/. "$out/lib/"

          for script in "$out"/bin/*; do
            sed -i '1c #!${ruby}/bin/ruby' "$script"
            ${lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # GetoptLong is a bundled gem; activate its loader explicitly
            # when the cross-built interpreter omits automatic gem startup.
            sed -i '2i require "rubygems"' "$script"
          ''}chmod 0755 "$script"
          done

          # The core snapshot tools need only ZFS and coreutils. The optional
          # database output supplies its own client path to the same scripts.
          sed -i "2iENV['PATH'] = '${runtimePath}:' + ENV.fetch('PATH', String.new)" \
            "$out/lib/zfstools.rb"

          mkdir -p "$db/bin"
          for script in zfs-auto-snapshot zfs-cleanup-snapshots zfs-snapshot-mysql; do
            cat > "$db/bin/$script" <<EOF
          #!${bash}/bin/bash
          export PATH='${databaseRuntimePath}':\$PATH
          exec "$out/bin/$script" "\$@"
          EOF
            chmod 0755 "$db/bin/$script"
          done

          "$out/bin/zfs-auto-snapshot" > usage.txt
          grep -q '^Usage:' usage.txt
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-zfstools";
        tool = self;
        extraDeps = [grep];
        command = "zfs-auto-snapshot > /tmp/zfstools-usage && grep -q '^Usage:' /tmp/zfstools-usage";
      };
    };

    meta = {
      description = "OpenSolaris-compatible automatic snapshot tools for ZFS";
      homepage = "https://github.com/bdrewery/zfstools";
      license = "BSD-2-Clause";
      mainProgram = "zfs-auto-snapshot";
    };
  }
