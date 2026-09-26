##! xfsprogs — XFS filesystem utilities (mkfs.xfs, xfs_repair, xfs_info, etc.)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gettext,
  inih,
  liburcu,
  util-linux,
}: let
  version = "7.1.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "xfsprogs";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Mkfs creates the image and xfs_db reports the canonical XFS magic value.";
        "files" = {
          "create.py" = "with open(\"image.xfs\", \"wb\") as image:\n    image.truncate(320 * 1024 * 1024)\n";
        };
        "input" = "A sparse 320 MiB regular file.";
        "operation" = "Create an XFS filesystem in the file and read its superblock magic through xfs_db.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "create.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/sbin/mkfs.xfs"
              "-f"
              "-q"
              "image.xfs"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/sbin/xfs_db"
              "-r"
              "-c"
              "sb 0"
              "-c"
              "p magicnum"
              "image.xfs"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "magicnum = 0x58465342\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Mkfs rejects the image size with a failure status.";
        "files" = {
          "create.py" = "with open(\"tiny.xfs\", \"wb\") as image:\n    image.truncate(1024 * 1024)\n";
        };
        "input" = "A sparse one-MiB file below XFS's minimum filesystem size.";
        "operation" = "Attempt to create an XFS filesystem in the undersized image.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "create.py"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@out@/sbin/mkfs.xfs"
              "-f"
              "-q"
              "tiny.xfs"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.edge.kernel.org/pub/linux/utils/fs/xfs/xfsprogs/xfsprogs-${version}.tar.xz"
      ];
      hash = "sha256-Bj7cMbqOhclcf6+b5GWgSJi7p8bmIv3ZsUbu1MpUFeg=";
    };

    buildDeps = [
      gnumake
      pkg-config
      gettext
    ];
    runtimeDeps = [util-linux inih liburcu];
    propagatedDeps = [util-linux inih liburcu];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd xfsprogs-${version}
          for f in install-sh libtool ltmain.sh config.guess config.sub depcomp missing compile; do
            if test -f "$f"; then
              sed -i '1s|^#! */bin/sh|#!'"$CONFIG_SHELL"'|; 1s|^#! */bin/bash|#!'"$CONFIG_SHELL"'|; 1s|^#! */usr/bin/env bash|#!'"$CONFIG_SHELL"'|' "$f"
            fi
          done
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --enable-lib64=no \
            --disable-blkid
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES V=1
        '';
      }
      {
        name = "install";
        script = ''
          make install
          make install-dev
        '';
      }
    ];

    meta = {
      description = "XFS filesystem utilities (mkfs.xfs, xfs_repair, xfs_info, etc.)";
      homepage = "https://xfs.wiki.kernel.org/";
      license = "GPL-2.0-only";
    };
  }
