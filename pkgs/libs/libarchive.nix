##! libarchive — Multi-format archive and compression library
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  openssl,
  zlib,
  zstd,
  bzip2,
  lz4,
  expat,
}: let
  version = "3.8.5";
in
  mkDerivation {
    pname = "libarchive";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.libarchive.org/downloads/libarchive-${version}.tar.xz"
      ];
      hash = "sha256-1oBo50vu46DsDdBK7pA31XV/zGUVkabc8bbVQvsVpwM=";
    };

    buildDeps = [
      make
      pkg-config
    ];
    runtimeDeps = [
      openssl
      zlib
      zstd
      bzip2
      lz4
      expat
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libarchive-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --with-openssl \
            --with-zlib \
            --with-zstd \
            --with-bz2lib \
            --without-xml2 \
            --with-expat \
            --with-lz4
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libarchive";
        library = self;
        libs = ["-larchive"];
        extraDeps = [
          pkgs.zlib
          pkgs.zstd
          pkgs.bzip2
          pkgs.lz4
          pkgs.openssl
          pkgs.xz
        ];
        testSource = ''
          #include <archive.h>
          #include <stdio.h>
          int main() {
            printf("libarchive version: %s\n", archive_version_string());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libarchive — multi-format archive and compression library";
      homepage = "https://www.libarchive.org";
      license = "BSD-2-Clause";
    };
  }
