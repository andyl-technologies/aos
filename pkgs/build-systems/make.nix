# GNU Make — Build automation tool
{ mkDerivation, fetchurl }:

let
  version = "4.4.1";
in
mkDerivation {
  pname = "make";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/make/make-${version}.tar.gz"
      "https://mirrors.kernel.org/gnu/make/make-${version}.tar.gz"
      "https://ftp.gnu.org/gnu/make/make-${version}.tar.gz"
    ];
    hash = "sha256-3Rb7HWe/q3mnL16DkHNcSePo5wtJRaFasfgd23hlj7M=";
  };

  buildDeps = [ ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd make-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
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
      '';
    }
  ];

  meta = {
    description = "GNU Make — a tool to control the generation of executables";
    homepage = "https://www.gnu.org/software/make/";
    license = "GPL-3.0-or-later";
  };
}
