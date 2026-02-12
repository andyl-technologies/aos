# GNU Bash — Bourne-Again SHell
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "5.2.32";
in
mkDerivation {
  pname = "bash";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/bash/bash-${version}.tar.gz"
      "https://mirrors.kernel.org/gnu/bash/bash-${version}.tar.gz"
      "https://ftp.gnu.org/gnu/bash/bash-${version}.tar.gz"
    ];
    hash = "sha256-0++A0rZ9jLvk0yZcY6csRvmyeOrW4OBtYYAbWPI/ULU=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd bash-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --without-bash-malloc \
          --with-installed-readline \
          --disable-nls
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
        ln -sf bash $out/bin/sh
      '';
    }
  ];

  meta = {
    description = "GNU Bash — the Bourne-Again SHell";
    homepage = "https://www.gnu.org/software/bash/";
    license = "GPL-3.0-or-later";
  };
}
