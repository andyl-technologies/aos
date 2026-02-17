##! git — Distributed version control system
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  perl,
  python3,
  autoconf,
  curl,
  openssl,
  zlib,
  expat,
  pcre2,
  gettext,
}: let
  version = "2.48.1";
in
  mkDerivation {
    pname = "git";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.edge.kernel.org/pub/software/scm/git/git-${version}.tar.xz"
        "https://www.kernel.org/pub/software/scm/git/git-${version}.tar.xz"
      ];
      hash = "sha256-HF1UX13B61HpXSxQ2Y/fiLGja6H6MOmuXVOFxgJPgq0=";
    };

    buildDeps = [
      make
      pkg-config
      perl
      python3
      autoconf
    ];
    runtimeDeps = [
      curl
      openssl
      zlib
      expat
      pcre2
      gettext
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd git-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          make configure
          ./configure \
            --prefix=$out \
            --with-curl=${curl} \
            --with-openssl=${openssl} \
            --with-expat=${expat} \
            --with-zlib=${zlib} \
            --with-pcre2=${pcre2} \
            --with-libpcre2 \
            --without-tcltk \
            --without-iconv
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES \
            NO_INSTALL_HARDLINKS=1 \
            PERL_PATH=${perl}/bin/perl \
            PYTHON_PATH=${python3}/bin/python3
        '';
      }
      {
        name = "install";
        script = ''
          make install \
            NO_INSTALL_HARDLINKS=1 \
            PERL_PATH=${perl}/bin/perl \
            PYTHON_PATH=${python3}/bin/python3
        '';
      }
    ];

    meta = {
      description = "git — distributed version control system";
      homepage = "https://git-scm.com";
      license = "GPL-2.0-only";
    };
  }
