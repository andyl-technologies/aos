##! elfutils — ELF utilities and libelf
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  zlib,
  m4,
  xz,
  bzip2,
  zstd,
}:

let
  version = "0.191";
in
mkDerivation {
  pname = "elfutils";
  inherit version;

  src = fetchurl {
    urls = [
      "https://sourceware.org/elfutils/ftp/${version}/elfutils-${version}.tar.bz2"
    ];
    hash = "sha256-33bbcTZtHXCDZfx6bGDKSDmPFDZ+sriVTvyIlxR62HE=";
  };

  buildDeps = [
    make
    pkg-config
    m4
  ];
  runtimeDeps = [
    zlib
    xz
    bzip2
    zstd
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd elfutils-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --program-prefix=eu- \
          --disable-debuginfod \
          --disable-libdebuginfod \
          --disable-demangler \
          --with-lzma \
          --with-bzlib \
          --with-zstd
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
    description = "elfutils — ELF utilities and libelf library";
    homepage = "https://sourceware.org/elfutils/";
    license = "GPL-3.0-or-later";
  };
}
