##! GNU Parted — Partition table editor and library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  check,
  gettext,
  lvm2,
  readline,
  util-linux,
  dosfstools,
  e2fsprogs,
  perl,
  python3,
  glibc-locales,
}: let
  version = "3.7";
in
  mkDerivation {
    pname = "parted";
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
    ];
    runtimeDeps = [gettext lvm2 readline util-linux];
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
        script = ''./configure $configureFlags --prefix="$out"'';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''
          export LOCPATH=${glibc-locales}/lib/locale
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
