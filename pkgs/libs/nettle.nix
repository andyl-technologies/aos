{
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  gmp,
}: let
  version = "3.10.1";
in
  mkDerivation {
    pname = "nettle";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/nettle/nettle-${version}.tar.gz"
        "https://mirrors.dotsrc.org/gnu/nettle/nettle-${version}.tar.gz"
      ];
      hash = "sha256-sPzdf8DN6m6A3PHdhbp5SvDVtKV+Jjl+7jvBkyctkTI=";
    };

    buildDeps = [gnumake m4];
    runtimeDeps = [gmp];
    propagatedDeps = [gmp];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd nettle-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --libdir=$out/lib \
            --disable-static \
            --enable-shared \
            --disable-documentation
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
      description = "Low-level cryptographic library (libnettle + libhogweed)";
      homepage = "https://www.lysator.liu.se/~nisse/nettle/";
      license = "LGPL-3.0-or-later";
    };
  }
