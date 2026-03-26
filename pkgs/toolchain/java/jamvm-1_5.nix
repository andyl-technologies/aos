##! jamvm-1_5 — JamVM 1.5.1 pure-C Java Virtual Machine
{
  mkDerivation,
  fetchurl,
  gnumake,
  classpath-0_93,
  zlib,
}:
let
  version = "1.5.1";
in
mkDerivation {
  pname = "jamvm-1_5";
  inherit version;

  src = fetchurl {
    urls = [
      "https://downloads.sourceforge.net/project/jamvm/jamvm/JamVM%20${version}/jamvm-${version}.tar.gz"
    ];
    hash = "sha256-ZjiVvWnK86H9pq9e6oJj2Qpf01yo9MMuIhCsQQeIkBo=";
  };

  buildDeps = [ gnumake ];
  runtimeDeps = [
    classpath-0_93
    zlib
  ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd jamvm-${version}
      '';
    }
    {
      name = "patch";
      script = ''
        # Add _GNU_SOURCE for pthread_getattr_np (GNU extension)
        sed -i '1i #define _GNU_SOURCE' src/os/linux/os.c
      '';
    }
    {
      name = "configure";
      script = ''
        CFLAGS="-O2 -std=gnu11 -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
        ./configure \
          --prefix=$out \
          --with-classpath-install-dir=${classpath-0_93}
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
        # Create java symlink so this can be used as JAVA_HOME
        ln -s jamvm $out/bin/java
      '';
    }
  ];

  meta = {
    description = "JamVM 1.5.1 — compact pure-C Java Virtual Machine";
    homepage = "https://jamvm.sourceforge.net/";
    license = "GPL-2.0";
  };
}
