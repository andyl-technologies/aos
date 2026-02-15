##! GNU Coreutils — Basic file, shell, and text utilities
{
  mkDerivation,
  fetchurl,
  make,
  openssl,
}:

let
  version = "9.5";
in
mkDerivation {
  pname = "coreutils";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/coreutils/coreutils-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/coreutils/coreutils-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/coreutils/coreutils-${version}.tar.xz"
    ];
    hash = "sha256-zTKO3qyS9qZl3p8yPJO3Eq8YWLwuDYjz9xAEaUcKG4o=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ openssl ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd coreutils-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --without-gmp \
          --with-openssl \
          --disable-nls \
          --enable-no-install-program=groups,hostname,kill,uptime
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
    description = "GNU Coreutils — basic file, shell, and text manipulation utilities";
    homepage = "https://www.gnu.org/software/coreutils/";
    license = "GPL-3.0-or-later";
  };
}
