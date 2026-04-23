##! semodule-utils — SELinux module utilities (semodule_package, etc.)
{
  mkDerivation,
  fetchurl,
  gnumake,
  libsepol,
}: let
  version = "3.10";
in
  mkDerivation {
    pname = "semodule-utils";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
      ];
      hash = "sha256-tHDgCV1FBpqAzs+Av5xRImQrycFU9BqnbTBQ6DfVmiA=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [libsepol];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd selinux-${version}/semodule-utils
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out BINDIR=$out/bin \
            -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out BINDIR=$out/bin
        '';
      }
    ];

    meta = {
      description = "semodule-utils — SELinux module packaging and expansion tools";
      homepage = "https://github.com/SELinuxProject/selinux";
      license = "GPL-2.0-or-later";
    };
  }
