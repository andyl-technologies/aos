##! git-2_42 -- Pinned minimum Git for registry compatibility tests
{
  mkDerivation,
  fetchurl,
  gnumake,
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
  version = "2.42.0";
in
  mkDerivation {
    pname = "git-2_42";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.edge.kernel.org/pub/software/scm/git/git-${version}.tar.xz"
        "https://www.kernel.org/pub/software/scm/git/git-${version}.tar.xz"
      ];
      hash = "sha256-MnghDp/SmUuEhN1+Pd2eqLlA71IXDNtgbaqU2IfJOw0=";
    };

    buildDeps = [
      gnumake
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
      description = "git 2.42.0 -- pinned registry compatibility floor";
      homepage = "https://git-scm.com";
      license = "GPL-2.0-only";
    };
  }
