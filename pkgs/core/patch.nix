# GNU Patch — Apply diff files to originals
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "patch-${versions.core.patch}";
  version = versions.core.patch;

  src = fetchurl {
    inherit (sources.patch) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd patch-${versions.core.patch}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out
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
    description = "GNU Patch — apply diff files to originals";
    homepage = "https://www.gnu.org/software/patch/";
    license = "GPL-3.0-or-later";
  };
}
