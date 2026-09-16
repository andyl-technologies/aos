##! kbd — Linux console keyboard and font utilities
{
  lib,
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
  version = "2.10.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "kbd";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "loadkeys accepts the mapping and emits its compiled table representation.";
        "files" = {
          "answer.map" = "keymaps 0\nkeycode 1 = Escape\n";
        };
        "input" = "A minimal Linux console keymap binding keycode 1 to Escape.";
        "operation" = "Parse the keymap and translate it into C tables with loadkeys.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/loadkeys"
              "-m"
              "answer.map"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "loadkeys rejects the invalid keycode with a non-success status.";
        "files" = {
          "invalid.map" = "keymaps 0\nkeycode not-a-number = Escape\n";
        };
        "input" = "A keymap declaration whose keycode is not numeric.";
        "operation" = "Parse the malformed mapping through loadkeys.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/loadkeys"
              "-m"
              "invalid.map"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://github.com/legionus/kbd/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-lvi2D5E26eC5JhueY7i0tFai+BeQHpA0lFM4elqh1Bw=";
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
