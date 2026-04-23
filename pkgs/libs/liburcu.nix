##! liburcu — Userspace Read-Copy-Update (RCU) library
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.14.1";
in
  mkDerivation {
    pname = "liburcu";
    inherit version;

    src = fetchurl {
      urls = [
        "https://lttng.org/files/urcu/userspace-rcu-${version}.tar.bz2"
      ];
      hash = "sha256-IxrLE9xuwCPoNqDwZm9qq0fcYh7LHSzZ2cIvkiZ4q8A=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd userspace-rcu-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
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
      description = "Userspace Read-Copy-Update (RCU) library";
      homepage = "https://liburcu.org/";
      license = "LGPL-2.1-or-later";
    };
  }
