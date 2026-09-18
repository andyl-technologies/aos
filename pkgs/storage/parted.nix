##! GNU Parted — Partition table editor and library
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
  pkg-config,
  check,
  gettext,
  lvm2,
  ncurses,
  readline,
  util-linux,
  dosfstools,
  e2fsprogs,
  perl,
  python3,
}: let
  version = "3.7";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "parted";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Parted accepts the image geometry and writes the partition table.";
        "files" = {};
        "input" = "A blank four-MiB disk image and a one-MiB partition extent.";
        "operation" = "Create a GPT label and partition through GNU Parted's script interface.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "open('disk.img', 'wb').truncate(4 * 1024 * 1024)"
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
              "@out@/sbin/parted"
              "-s"
              "disk.img"
              "mklabel"
              "gpt"
              "mkpart"
              "primary"
              "1MiB"
              "2MiB"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@out@/sbin/parted"
              "-s"
              "disk.img"
              "unit"
              "s"
              "print"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Parted rejects the label with a non-success status.";
        "files" = {};
        "input" = "A partition-table label name unsupported by GNU Parted.";
        "operation" = "Attempt to create the unknown label on a local image.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "open('disk.img', 'wb').truncate(4 * 1024 * 1024)"
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
              "@out@/sbin/parted"
              "-s"
              "disk.img"
              "mklabel"
              "qualification-label-does-not-exist"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;
    src = fetchurl {
      urls = ["https://ftpmirror.gnu.org/parted/parted-${version}.tar.xz"];
      hash = "sha256-AI3ldWGk88JaBkjmbtEeezC+STiJtkM0ptcPLBlR73s=";
    };
    buildDeps = [
      gnumake
      pkg-config
      check
      dosfstools
      e2fsprogs
      perl
      python3
      buildPackages.glibc-locales
    ];
    # The interactive CLI links ncurses directly alongside readline.
    runtimeDeps = [gettext lvm2 ncurses readline util-linux];
    propagatedDeps = [util-linux];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd parted-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          find tests -type f | while read -r script; do
            first=$(head -n 1 "$script" 2>/dev/null || true)
            case "$first" in
              '#!'*python*) sed -i "1s|.*|#!${python3}/bin/python3|" "$script" ;;
              '#!'*perl*) sed -i "1s|.*|#!${perl}/bin/perl|" "$script" ;;
              '#!'*sh*|'#!'*bash*) sed -i "1s|.*|#!$CONFIG_SHELL|" "$script" ;;
            esac
          done
        '';
      }
      {
        name = "configure";
        script =
          lib.optionalString (stdenv.isCross && stdenv.hostPlatform.isLinux) ''
            # The test executables run on the target, so their Check library
            # must not come from the native build dependency splice.
            export PKG_CONFIG_PATH=${check}/lib/pkgconfig:$PKG_CONFIG_PATH
          ''
          + ''./configure $configureFlags --prefix="$out"'';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''
          export LOCPATH=${buildPackages.glibc-locales}/lib/locale
          export LC_ALL=C.UTF-8
          make check
        '';
      }
      {
        name = "install";
        script = ''
          make install
          "$out/sbin/parted" --version | grep -q '${version}'
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-parted";
        library = self;
        libs = ["-lparted"];
        testSource = ''
          #include <parted/parted.h>
          int main(void) {
            ped_exception_fetch_all();
            return 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-parted";
        tool = self;
        command = "parted --version | grep -q '${version}'";
      };
    };
    meta = {
      description = "Creates, destroys, resizes, checks, and copies disk partitions";
      homepage = "https://www.gnu.org/software/parted/";
      license = "GPL-3.0-or-later";
      mainProgram = "parted";
    };
  }
