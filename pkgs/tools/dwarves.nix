##! dwarves - DWARF/BTF inspection tools including pahole
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  pkg-config,
  elfutils,
  zlib,
  xz,
  bzip2,
  zstd,
  libbpf,
}: let
  version = "1.31";
in
  mkDerivation {
    pname = "dwarves";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/acmel/dwarves/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-K2URaRvaKzrjKJhwkpAtMP0HPvfIdUiU9KaScaZmhvI=";
    };

    buildDeps = [
      cmake
      ninja
      pkg-config
    ];
    runtimeDeps = [
      elfutils
      zlib
      xz
      bzip2
      zstd
      libbpf
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd dwarves-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DLIB_INSTALL_DIR=lib \
            -DLIBBPF_EMBEDDED=OFF \
            -DDWARF_INCLUDE_DIR=${elfutils}/include \
            -DLIBDW_INCLUDE_DIR=${elfutils}/include \
            -DDWARF_LIBRARY=${elfutils}/lib/libdw.so \
            -DELF_LIBRARY=${elfutils}/lib/libelf.so \
            -DZLIB_LIBRARY=${zlib}/lib/libz.so \
            -DZLIB_INCLUDE_DIR=${zlib}/include
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-dwarves-pahole";
        tool = self;
        command = "pahole --version";
      };
    };

    meta = {
      description = "dwarves - DWARF/BTF inspection tools including pahole";
      homepage = "https://github.com/acmel/dwarves";
      license = "GPL-2.0-only";
    };
  }
