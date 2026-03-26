##! elfutils — ELF utilities and libelf
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  zlib,
  m4,
  xz,
  bzip2,
  zstd,
}:
let
  version = "0.192";
in
mkDerivation {
  pname = "elfutils";
  inherit version;

  src = fetchurl {
    urls = [
      "https://sourceware.org/elfutils/ftp/${version}/elfutils-${version}.tar.bz2"
    ];
    hash = "sha256-YWCZvq4kq6Efm2PYbKbMjVZtlouAI5EzTJHfVOq0FrQ=";
  };

  buildDeps = [
    gnumake
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

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      link = testing.mkLinkCheck {
        pname = "lib-elfutils";
        library = self;
        libs = [ "-lelf" ];
        testSource = ''
          #include <libelf.h>
          #include <stdio.h>
          int main() {
            if (elf_version(EV_CURRENT) == EV_NONE) return 1;
            printf("elfutils libelf: PASS\n");
            return 0;
          }
        '';
      };
    };

  meta = {
    description = "elfutils — ELF utilities and libelf library";
    homepage = "https://sourceware.org/elfutils/";
    license = "GPL-3.0-or-later";
  };
}
