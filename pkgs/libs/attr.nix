##! attr — userspace library and tools for POSIX extended attributes
{
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
}: let
  version = "2.6.0";
in
  mkDerivation {
    pname = "attr";
    inherit version;

    src = fetchurl {
      name = "attr-${version}.tar.xz";
      urls = [
        "https://mirror.fi.ossplanet.net/nongnu/attr/attr-${version}.tar.xz"
        "https://download.savannah.gnu.org/releases/attr/attr-${version}.tar.xz"
        "https://download-mirror.savannah.gnu.org/releases/attr/attr-${version}.tar.xz"
      ];
      hash = "sha256-bIohSKe4UEO2hJK85DMWsOLiFPxOYox+3geOduIWMws=";
    };

    buildDeps = [gnumake gettext];
    runtimeDeps = [];
    propagatedDeps = [];

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
