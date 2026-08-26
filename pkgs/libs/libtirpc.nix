##! libtirpc — Transport Independent RPC library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  stdenv,
}: let
  version = "1.3.7";
in
  mkDerivation {
    pname = "libtirpc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://sourceforge.net/projects/libtirpc/files/libtirpc/${version}/libtirpc-${version}.tar.bz2"
      ];
      hash = "sha256-tH06wZ01SeVKBdABmmxABnTacWEjhYz9ttO91wpmxwI=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libtirpc-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            CPPFLAGS="-D__APPLE_USE_RFC_3542" ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-gssapi
            sed -i 's/-Wl,--no-undefined//g' src/Makefile
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-gssapi
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

    meta = {
      description = "libtirpc — Transport Independent RPC library";
      homepage = "https://sourceforge.net/projects/libtirpc/";
      license = "BSD-3-Clause";
    };
  }
