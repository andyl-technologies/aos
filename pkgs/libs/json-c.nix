##! json-c — JSON parser/generator for C
{
  mkDerivation,
  fetchurl,
  stdenv,
  cmake,
  gnumake,
  pkg-config,
}: let
  version = "0.18";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    pname = "json-c";
    inherit version;

    src = fetchurl {
      urls = [
        "https://s3.amazonaws.com/json-c_releases/releases/json-c-${version}.tar.gz"
        "https://github.com/json-c/json-c/archive/refs/tags/json-c-${version}-20240915.tar.gz"
      ];
      hash = "sha256-h2qwRkeRZrhpr8aJbSiBg7vA5YQ/FBIAxnez6N+xFyQ=";
    };

    buildDeps = [
      cmake
      gnumake
      pkg-config
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if isDarwinCross
          then ''
            tar xf $src
            cd json-c-${version}

            # Cross CMake uses static-library try-compiles, which falsely
            # report ELF-only linker switches as supported. Keep the probes
            # for other hosts, but never apply them to a Mach-O link.
            sed -i \
              -e 's/if (DISABLE_BSYMBOLIC STREQUAL "OFF" AND BSYMBOLIC_WORKS)/if (DISABLE_BSYMBOLIC STREQUAL "OFF" AND BSYMBOLIC_WORKS AND NOT APPLE)/' \
              -e 's/if (VERSION_SCRIPT_WORKS)/if (VERSION_SCRIPT_WORKS AND NOT APPLE)/' \
              CMakeLists.txt
          ''
          else ''
            tar xf $src
            cd json-c-${version}
          '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DBUILD_SHARED_LIBS=ON \
            -DBUILD_STATIC_LIBS=OFF \
            -DBUILD_APPS=OFF \
            -DBUILD_TESTING=OFF \
            -DDISABLE_WERROR=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build . -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install .
        '';
      }
    ];

    meta = {
      description = "JSON parser and generator for C";
      homepage = "https://github.com/json-c/json-c";
      license = "MIT";
    };
  }
