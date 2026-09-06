##! kbd — Linux console keyboard and font utilities
{
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  libtool,
  gettext,
  gnumake,
  pkg-config,
  flex,
  bison,
  perl,
  check,
  which,
  linux-pam,
  zlib,
  bzip2,
  xz,
  zstd,
  coreutils,
}: let
  version = "2.9.0";
in
  mkDerivation {
    pname = "kbd";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/legionus/kbd/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-+kk7W2pvdJxnS85PAa6cR4l2ZU8sKCHLCmbHQ242abI=";
    };

    buildDeps = [autoconf automake libtool gettext gnumake pkg-config flex bison perl check which];
    runtimeDeps = [zlib bzip2 xz zstd coreutils linux-pam];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd kbd-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          find contrib -type f | while read -r script; do
            first=$(head -n 1 "$script" 2>/dev/null || true)
            case "$first" in
              '#!'*perl*) sed -i "1s|^#!.*|#!${perl}/bin/perl|" "$script" ;;
              '#!'*) sed -i "1s|^#!.*|#!$CONFIG_SHELL|" "$script" ;;
            esac
          done
          sed -i \
            -e 's|/usr/bin/tty|${coreutils}/bin/tty|g' \
            -e 's|/bin/tty|${coreutils}/bin/tty|g' \
            src/unicode_start src/unicode_stop
          sed -i \
            's|$OPT -I m4|$OPT -I m4 -I ${pkg-config}/share/aclocal|' \
            autogen.sh
        '';
      }
      {
        name = "configure";
        script = ''
          export PATH=${gettext}/bin:$PATH
          export AUTOPOINT=${gettext}/bin/autopoint
          ./autogen.sh
          ./configure $configureFlags \
            --prefix="$out" \
            --enable-optional-progs \
            --enable-libkeymap
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''make check'';
      }
      {
        name = "install";
        script = ''
          make install
          "$out/bin/loadkeys" --version | grep -q '${version}'
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-kbd";
        tool = self;
        command = "loadkeys --version && dumpkeys --help >/dev/null";
      };
    };

    meta = {
      description = "Provides Linux console keymaps, fonts, and keyboard utilities";
      homepage = "https://kbd-project.org/";
      license = "GPL-2.0-or-later";
      mainProgram = "loadkeys";
    };
  }
