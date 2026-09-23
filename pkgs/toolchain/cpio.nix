##! cpio — GNU cpio archive utility
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2.15";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "cpio";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Cpio emits the exact archived path when reading its own archive.";
        "files" = {
          "payload.txt" = "cpio payload\n";
        };
        "input" = "A file name and payload to store in a newc archive.";
        "operation" = "Create the archive from the name list, then list its stored member.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/cpio"
              "--create"
              "--format=newc"
              "--file=archive.cpio"
            ];
            "exit_code" = 0;
            "stdin" = "payload.txt\n";
          }
          {
            "argv" = [
              "@out@/bin/cpio"
              "--list"
              "--file=archive.cpio"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "payload.txt\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Cpio rejects the invalid archive with status 2.";
        "files" = {
          "invalid.cpio" = "not a cpio archive\n";
        };
        "input" = "A text file that is not any supported cpio archive format.";
        "operation" = "List members from the malformed archive.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/cpio"
              "--list"
              "--file=invalid.cpio"
            ];
            "exit_code" = 2;
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
        "https://ftp.gnu.org/gnu/cpio/cpio-${version}.tar.gz"
      ];
      hash = "sha256-76UO+YMTfu/AoC/bUVCdYkteMpXJgKoSfO7kGDRVSZ4=";
    };

    buildDeps = [
      gnumake
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd cpio-${version}
          # The trailing symlink-name buffer is larger than one byte. Give it
          # a flexible-array type so Fortify 3 accepts valid link targets.
          sed -i 's/char target\[1\];/char target[];/' src/copyin.c
          sed -i 's/sizeof (\*p) + strlen (oldpath) + newlen + 1/sizeof (*p) + strlen (oldpath) + newlen + 2/' src/copyin.c
          grep -Fq 'char target[];' src/copyin.c
        '';
      }
      {
        name = "build";
        script = ''
          CFLAGS="-O2 -std=gnu17" $CONFIG_SHELL ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-nls
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "GNU cpio — archive utility";
      homepage = "https://www.gnu.org/software/cpio/";
      license = "GPL-3.0-or-later";
    };
  }
