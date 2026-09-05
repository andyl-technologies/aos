##! fstrm — Frame Streams implementation in C
{
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  automake,
  libtool,
  m4,
  pkg-config,
  libevent,
  openssl,
}: let
  version = "0.6.1";
in
  mkDerivation {
    pname = "fstrm";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/farsightsec/fstrm/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-Tw960rdgEZxEGrpYJx6E3mg7PME4Uw0CcQiWZBhm4tI=";
    };

    buildDeps = [gnumake autoconf automake libtool m4 pkg-config];
    runtimeDeps = [libevent openssl];
    propagatedDeps = [libevent];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd fstrm-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export ACLOCAL_PATH="${libtool}/share/aclocal:${pkg-config}/share/aclocal''${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
          autoreconf -fi
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-shared \
            --enable-static
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-fstrm";
        library = self;
        libs = ["-lfstrm"];
        testSource = ''
          #include <fstrm.h>

          int main(void) {
              struct fstrm_writer_options *options = fstrm_writer_options_init();
              if (options == NULL) return 1;
              fstrm_writer_options_destroy(&options);
              return options == NULL ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "Frame Streams implementation in C";
      homepage = "https://github.com/farsightsec/fstrm";
      license = "Apache-2.0";
    };
  }
