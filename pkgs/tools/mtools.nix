##! mtools — utilities for accessing MS-DOS disks
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  stdenv,
}: let
  version = "4.0.49";
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
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "mtools";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The FAT image preserves the file's exact contents.";
        "files" = {
          "answer.txt" = "answer=42\n";
        };
        "input" = "A blank 1.44 MiB disk image and a text file containing answer=42.";
        "operation" = "Format the image as FAT, copy the file into it, and read the file back through mtools.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "open('disk.img', 'wb').truncate(1474560)"
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
              "@out@/bin/mformat"
              "-i"
              "disk.img"
              "-f"
              "1440"
              "::"
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
              "@out@/bin/mcopy"
              "-i"
              "disk.img"
              "answer.txt"
              "::ANSWER.TXT"
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
              "@out@/bin/mtype"
              "-i"
              "disk.img"
              "::ANSWER.TXT"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "answer=42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "mformat rejects the malformed numeric size with a non-success status.";
        "files" = {};
        "input" = "A floppy-size argument containing non-numeric text.";
        "operation" = "Parse the malformed geometry through mformat.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/mformat"
              "-f"
              "not-a-number"
              "::"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/mtools/mtools-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/mtools/mtools-${version}.tar.gz"
      ];
      hash = "sha256-EM0REdqHvyQAo4DBY5psuov7k3ok+cUfX4jTk65fb3Y=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [bash]
      else [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd mtools-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --without-x
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            for script in amuFormat.sh mcheck mcomp mxtar tgz uz; do
              [ -f "$out/bin/$script" ] || continue
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/$script"
            done
            # The image finalizer executes an exact regular file, not a symlink.
            rm "$out/bin/mcopy"
            cp "$out/bin/mtools" "$out/bin/mcopy"
          ''
          else ''
            make install
            rm "$out/bin/mcopy"
            cp "$out/bin/mtools" "$out/bin/mcopy"
          '';
      }
    ];

    meta = {
      description = "mtools — utilities for accessing MS-DOS disks";
      homepage = "https://www.gnu.org/software/mtools/";
      license = "GPL-3.0-or-later";
    };
  }
