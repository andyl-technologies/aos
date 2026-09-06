##! libpsl — Public Suffix List library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  python3,
  libidn2,
  libunistring,
  publicsuffix-list,
}: let
  version = "0.21.5";
in
  mkDerivation {
    pname = "libpsl";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/rockdaboot/libpsl/releases/download/${version}/libpsl-${version}.tar.gz"];
      hash = "sha256-Hcyc6uixKPPAs/ZU3s0OHoka/G/4EJjyJ+8mBEna4gg=";
    };

    buildDeps = [gnumake pkg-config python3];
    runtimeDeps = [libidn2 libunistring publicsuffix-list];
    propagatedDeps = [libidn2 libunistring];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libpsl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-runtime=libidn2 \
            --enable-builtin \
            --disable-man \
            --with-psl-distfile="${publicsuffix-list}/share/publicsuffix/public_suffix_list.dat" \
            --with-psl-file="${publicsuffix-list}/share/publicsuffix/public_suffix_list.dat" \
            --with-psl-testfile="${publicsuffix-list}/share/publicsuffix/test_psl.txt"
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
        pname = "lib-libpsl";
        library = self;
        libs = ["-lpsl"];
        testSource = ''
          #include <libpsl.h>

          int main(void) {
              const psl_ctx_t *ctx = psl_builtin();
              return ctx != 0 && psl_is_public_suffix(ctx, "com") ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "C library for the Public Suffix List";
      homepage = "https://rockdaboot.github.io/libpsl/";
      license = "MIT";
      mainProgram = "psl";
    };
  }
