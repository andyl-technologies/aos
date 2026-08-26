##! Node.js — JavaScript runtime built on V8.
##!
##! Built hermetically from source. Node bundles its own V8, ICU, zlib,
##! libuv, c-ares, nghttp2, and OpenSSL, so this package uses the bundled
##! dependencies exclusively (no `--shared-*` system libraries) to keep the
##! build self-contained. The build is python-driven (`configure.py` plus the
##! GYP-generated Makefiles); `PYTHON` is pinned to the AOS python3 so no host
##! interpreter is consulted.
{
  mkDerivation,
  fetchurl,
  python3,
  gnumake,
  stdenv,
  buildPackages,
}: let
  version = "22.22.3";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildPython =
    if isDarwinCross
    then buildPackages.python3
    else python3;
  targetCpu =
    if stdenv.hostPlatform.isAarch64
    then "arm64"
    else "x64";
in
  mkDerivation {
    pname = "nodejs";
    inherit version;

    src = fetchurl {
      urls = [
        "https://nodejs.org/dist/v${version}/node-v${version}.tar.xz"
      ];
      hash = "sha256-8+aleNsaszWkpyeFweh60Yos9tL8JXR6HXQfs0rwvQ8=";
    };

    buildDeps =
      [
        python3
        gnumake
      ]
      ++ (
        if isDarwinCross
        then [buildPython]
        else []
      );
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd node-v${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # No /usr/bin/env in the sandbox: pin every python invocation to the
          # AOS interpreter. configure.py honors $PYTHON; the generated build
          # rules invoke it via the same variable through the Makefile.
          export PYTHON=${buildPython}/bin/python3
          ${
            if isDarwinCross
            then ''
              export CC_host=${buildPackages.cc}/bin/cc
              export CXX_host=${buildPackages.cc}/bin/c++
            ''
            else ""
          }

          # V8 and Node embed an absolute RPATH-free shared object set; the
          # ccWrapper already injects -Wl,-rpath for runtime deps. Bundled
          # OpenSSL/ICU/zlib mean we link nothing from the system.
          # Omit --ninja: it is a store-true flag, and leaving it off makes
          # configure.py emit GYP Makefiles driven by AOS gnumake.
          $PYTHON configure.py \
            --prefix=$out \
            --with-intl=full-icu \
            ${
            if isDarwinCross
            then ''--cross-compiling --dest-os=mac --dest-cpu=${targetCpu}''
            else ""
          }
        '';
      }
      {
        name = "build";
        script = ''
          export PYTHON=${buildPython}/bin/python3
          ${
            if isDarwinCross
            then ''
              make -j$NIX_BUILD_CORES PYTHON=$PYTHON \
                CC.host=${buildPackages.cc}/bin/cc \
                CXX.host=${buildPackages.cc}/bin/c++
            ''
            else "make -j$NIX_BUILD_CORES PYTHON=$PYTHON"
          }
        '';
      }
      {
        name = "install";
        script = ''
          export PYTHON=${buildPython}/bin/python3
          make install PYTHON=$PYTHON
        '';
      }
    ];

    meta = {
      description = "Node.js — JavaScript runtime built on V8";
      homepage = "https://nodejs.org/";
      license = "MIT";
    };
  }
