##! dtc — Device Tree Compiler and flattened device tree library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
  libyaml,
}: let
  version = "1.7.2";
in
  mkDerivation {
    pname = "dtc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.edge.kernel.org/pub/software/utils/dtc/dtc-${version}.tar.xz"
      ];
      hash = "sha256-ktjKdpgFrh8XYgQjBDj+UoCPThx5RAU8nuwOZJsjdTk=";
    };

    buildDeps = [
      gnumake
      pkg-config
      flex
      bison
    ];
    runtimeDeps = [libyaml];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd dtc-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES NO_PYTHON=1
        '';
      }
      {
        name = "install";
        script = ''
          make NO_PYTHON=1 PREFIX=$out install
        '';
      }
    ];

    meta = {
      description = "Device Tree Compiler and flattened device tree library";
      homepage = "https://git.kernel.org/pub/scm/utils/dtc/dtc.git";
      license = "GPL-2.0-or-later";
    };
  }
