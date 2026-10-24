##! HDF5 — Hierarchical scientific data storage with C and C++ APIs
{
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
  buildPackages,
  stdenv,
  zlib,
  libaec,
}: let
  version = "1.14.6";
  buildMake = buildPackages.writeShellScriptBin "make" ''
    exec ${buildPackages.gnumake}/bin/make SHELL=${buildPackages.bash}/bin/bash "$@"
  '';
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = [stdenv.buildPlatform.constraints.cpu];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };

    pname = "hdf5";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/HDFGroup/hdf5/releases/download/hdf5_${version}/hdf5-${version}.tar.gz"];
      hash = "sha256-5N77rDD1DWThVWN0qknldEF8nnLGsd56T/iMSxvqbps=";
    };

    buildDeps = [cmake gnumake buildMake];
    runtimeDeps = [zlib libaec];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd hdf5-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build \
            -DCMAKE_MAKE_PROGRAM=${buildMake}/bin/make \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=ON \
            -DHDF5_BUILD_CPP_LIB=ON \
            -DHDF5_ENABLE_SZIP_ENCODING=ON \
            -Dlibaec_DIR=${libaec}/lib/cmake/libaec \
            -DZLIB_ROOT=${zlib}
          test "$(sed -n 's/^#define H5_HAVE_FILTER_SZIP //p' build/src/H5pubconf.h)" = 1
        '';
      }
      {
        name = "build";
        script = ''cmake --build build --parallel "$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''ctest --test-dir build --output-on-failure -R '^(H5TEST-testhdf5-base|CPP_testhdf5)$' --no-tests=error'';
      }
      {
        name = "install";
        script = ''
          cmake --install build
          mkdir -p "$out/share/licenses/hdf5"
          cp COPYING "$out/share/licenses/hdf5/COPYING"
        '';
      }
    ];

    meta = {
      description = "Hierarchical data storage libraries and tools with C and C++ interfaces";
      homepage = "https://www.hdfgroup.org/solutions/hdf5/";
      license = "BSD-3-Clause";
      mainProgram = "h5dump";
    };
  }
