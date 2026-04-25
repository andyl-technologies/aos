##! lsof — List open files
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  linux-headers,
  libtirpc,
}: let
  version = "4.99.4";
in
  mkDerivation {
    pname = "lsof";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/lsof-org/lsof/releases/download/${version}/lsof-${version}.tar.gz"
      ];
      hash = "sha256-DEROLavsFK0UbLt/W1K1q0l2coQC/zSNn+ztmtl0DGY=";
    };

    buildDeps = [
      gnumake
      pkg-config
      linux-headers
    ];
    runtimeDeps = [libtirpc];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd lsof-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-dependency-tracking \
            --with-libtirpc
        '';
      }
      {
        name = "build";
        script = ''
          cat > soelim-wrapper <<'SCRIPT'
          #!/bin/sh
          cat "$@"
          SCRIPT
          chmod +x soelim-wrapper
          PATH="$PWD:$PATH"
          ln -s soelim-wrapper soelim
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
      description = "List open files";
      homepage = "https://github.com/lsof-org/lsof";
      license = "lsof";
    };
  }
