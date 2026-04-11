##! attr — userspace library and tools for POSIX extended attributes
{
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
}:
let
  version = "2.5.2";
in
mkDerivation {
  pname = "attr";
  inherit version;

  src = fetchurl {
    urls = [
      "https://download.savannah.gnu.org/releases/attr/attr-${version}.tar.gz"
      "https://mirrors.kernel.org/gnu/attr/attr-${version}.tar.gz"
    ];
    hash = "sha256-Ob9nRS+kHQlIwhl2AQU/SLPXigKTiXNDMqYwmmgMbIc=";
  };

  buildDeps = [
    gnumake
    gettext
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd attr-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-static \
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
    description = "Library and tools for manipulating POSIX extended attributes";
    homepage = "https://savannah.nongnu.org/projects/attr/";
    license = "LGPL-2.1-or-later";
  };
}
