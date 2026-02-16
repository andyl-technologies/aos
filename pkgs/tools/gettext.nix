##! gettext — GNU internationalization and localization tools
{
  mkDerivation,
  fetchurl,
  make,
  ncurses,
  libxcrypt,
}:

let
  version = "0.22.5";
in
mkDerivation {
  pname = "gettext";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/gettext/gettext-${version}.tar.gz"
      "https://ftp.gnu.org/gnu/gettext/gettext-${version}.tar.gz"
    ];
    hash = "sha256-7BcFselpuDqfBzFE7IBhUduIEn9eQP5alMtsj6SJlqA=";
  };

  buildDeps = [ make ];
  runtimeDeps = [
    ncurses
    libxcrypt
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd gettext-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-static \
          --disable-java \
          --disable-csharp \
          --with-included-libxml \
          --with-included-libunistring \
          --without-emacs \
          --without-git
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
    description = "gettext — GNU internationalization and localization tools";
    homepage = "https://www.gnu.org/software/gettext/";
    license = "GPL-3.0-or-later";
  };
}
