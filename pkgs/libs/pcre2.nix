##! pcre2 — Perl Compatible Regular Expressions (version 2)
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "10.47";
in
  mkDerivation {
    pname = "pcre2";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${version}/pcre2-${version}.tar.bz2"
      ];
      hash = "sha256-R/6MmUYSUNQviebo/a66naBXhV0G63/AjZygP9CNe8c=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pcre2-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --enable-unicode \
            --enable-pcre2-8 \
            --enable-pcre2-16 \
            --enable-pcre2-32 \
            --enable-jit=auto \
            --enable-jit-sealloc
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
        script = ''
          make install
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libpcre2-8.so"];
      };

      link = testing.mkLinkCheck {
        pname = "lib-pcre2";
        library = self;
        libs = ["-lpcre2-8"];
        testSource = ''
          #define PCRE2_CODE_UNIT_WIDTH 8
          #include <pcre2.h>
          #include <stdio.h>
          int main() {
            int major = PCRE2_MAJOR;
            int minor = PCRE2_MINOR;
            printf("pcre2 version: %d.%d\n", major, minor);
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "pcre2 — Perl Compatible Regular Expressions (version 2)";
      homepage = "https://www.pcre.org/";
      license = "BSD-3-Clause";
    };
  }
