##! Build-machine GNU assembler for Highway's newer x86 SIMD encodings.
{
  buildPackages,
  fetchurl,
}: let
  version = "2.45.1";
in
  buildPackages.mkDerivation {
    pname = "highway-assembler";
    inherit version;
    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/binutils/binutils-${version}.tar.xz"];
      hash = "199sa5igipbvz2zg0j1zgvrybphgcznq2bcnjpngs64xzvk03qaz";
    };

    buildDeps = [buildPackages.gnumake buildPackages.texinfo buildPackages.gettext];
    runtimeDeps = [buildPackages.zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd binutils-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          $CONFIG_SHELL ../configure --prefix="$out" --disable-werror --with-system-zlib
        '';
      }
      {
        name = "build";
        script = ''
          # Only the assembler is consumed here; the existing linker remains
          # part of the compiler wrapper's toolchain.
          make -j"$NIX_BUILD_CORES" all-gas
        '';
      }
      {
        name = "install";
        script = ''
          make install-gas
          test -x "$out/bin/as"
          mkdir -p "$out/share/licenses/highway-assembler"
          cp ../COPYING3 "$out/share/licenses/highway-assembler/"
        '';
      }
    ];

    meta = {
      description = "GNU assembler with AVX10.2 instruction encoding support";
      homepage = "https://sourceware.org/binutils/";
      license = "GPL-3.0-or-later";
    };
  }
