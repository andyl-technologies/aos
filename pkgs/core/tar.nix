# GNU Tar — Archiving utility
{ mkDerivation, fetchurl, make }:

let version = "1.35"; in
mkDerivation {
  pname = "tar";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/tar/tar-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/tar/tar-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/tar/tar-${version}.tar.xz"
    ];
    hash = "sha256-TWL/NzQux67XSFNTI5MMfPlKz3HDWRiCsmp+pQ8+3BY=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd tar-${version}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-nls
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install
      '';
    }
  ];

  meta = {
    description = "GNU Tar — archiving utility";
    homepage = "https://www.gnu.org/software/tar/";
    license = "GPL-3.0-or-later";
  };
}
