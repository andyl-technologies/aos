##! acl — POSIX Access Control Lists userspace library and tools
{
  mkDerivation,
  fetchurl,
  gnumake,
  gettext,
  attr,
}: let
  version = "2.3.2";
in
  mkDerivation {
    pname = "acl";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.savannah.gnu.org/releases/acl/acl-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/acl/acl-${version}.tar.gz"
      ];
      hash = "sha256-XyvbrWKXB6p9hcYj+ZSqih0t7FWnPeUgW6wL9gWKL3w=";
    };

    buildDeps = [
      gnumake
      gettext
    ];
    runtimeDeps = [attr];
    propagatedDeps = [attr];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd acl-${version}
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
      description = "POSIX Access Control Lists userspace library and tools";
      homepage = "https://savannah.nongnu.org/projects/acl/";
      license = "LGPL-2.1-or-later";
    };
  }
