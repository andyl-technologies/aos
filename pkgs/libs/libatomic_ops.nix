##! libatomic_ops — portable atomic memory operations library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "7.8.2";
in
  mkDerivation {
    pname = "libatomic_ops";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/ivmai/libatomic_ops/releases/download/v${version}/libatomic_ops-${version}.tar.gz"
      ];
      hash = "sha256-0wUgf+IH8rP7XLTAGdoStEzj/LxZPf1QgNhnsaJBm1E=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libatomic_ops-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --enable-shared \
            --disable-static
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
      description = "Portable atomic memory operations library";
      homepage = "https://github.com/ivmai/libatomic_ops";
      # The core library is MIT; the separately installed gpl extension is
      # GPL-2.0-only. The package output contains both components.
      license = ["MIT" "GPL-2.0-only"];
    };
  }
