##! jamvm-2_0 — JamVM 2.0.0 Java Virtual Machine with Classpath 0.99
{
  mkDerivation,
  fetchurl,
  gnumake,
  classpath-0_99,
  zlib,
}:
let
  version = "2.0.0";
in
mkDerivation {
  pname = "jamvm-2_0";
  inherit version;

  src = fetchurl {
    urls = [
      "https://downloads.sourceforge.net/project/jamvm/jamvm/JamVM%20${version}/jamvm-${version}.tar.gz"
    ];
    hash = "sha256-dkKOlt8K6d2WTHp8dMHpqDfi8xLDnpo1f6gXj37/gNo=";
  };

  buildDeps = [ gnumake ];
  runtimeDeps = [
    classpath-0_99
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
        sed -i '1i #define _GNU_SOURCE' src/os/linux/os.c 2>/dev/null || true
      '';
    }
    {
      name = "configure";
      script = ''
        CFLAGS="-O2 -std=gnu11 -Wno-error -Wno-implicit-function-declaration -Wno-incompatible-pointer-types" \
        ./configure \
          --prefix=$out \
          --with-classpath-install-dir=${classpath-0_99}
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
    description = "JamVM 2.0.0 — Java Virtual Machine with Classpath 0.99";
    homepage = "https://jamvm.sourceforge.net/";
    license = "GPL-2.0";
  };
}
