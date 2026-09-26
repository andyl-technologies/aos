##! OpenEXR — high-dynamic-range image libraries and tools.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  imath,
  libdeflate,
  openjph,
}: let
  version = "3.4.15";
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
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "openexr";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/AcademySoftwareFoundation/openexr/archive/refs/tags/v${version}.tar.gz"];
      hash = "1amxprzv1f9sfk5mrinyc4xi52v237j1kwm4wf5zk72dxaqdapj4";
    };

    buildDeps = [buildPackages.cmake buildPackages.gnumake buildPackages.pkg-config buildPackages.python3 buildPackages.help2man];
    runtimeDeps = [imath libdeflate openjph];
    # Downstream pkg-config queries also resolve the private codec requirements.
    propagatedDeps = [imath libdeflate openjph];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd openexr-${version}
            # Test fixtures belong in the sandbox's writable temporary directory.
            sed -i "s|/var/tmp/|$TMPDIR/|g" \
              src/test/OpenEXRCoreTest/main.cpp src/test/OpenEXRTest/tmpDir.h
            ${
              if stdenv.isCross
              then ''
                # help2man executes each tool. Use the matching native build for
                # documentation while compiling the target libraries and tools.
                sed -i 's|''${CMAKE_CURRENT_BINARY_DIR}/../bin/|${buildPackages.openexr}/bin/|g' docs/CMakeLists.txt
              ''
              else ""
            }
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_PREFIX_PATH="${imath};${libdeflate};${openjph}" \
              -DFETCHCONTENT_FULLY_DISCONNECTED=ON -DBUILD_TESTING=ON \
              -DOPENEXR_INSTALL_DOCS=ON -DOPENEXR_INSTALL_DEVELOPER_TOOLS=ON
          '';
        }
        {
          name = "build";
          script = ''
            cmake --build build --parallel "$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              ctest --test-dir build --output-on-failure --parallel "$NIX_BUILD_CORES"
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            cmake --install build
            mkdir -p "$out/share/licenses/openexr"
            cp LICENSE.md "$out/share/licenses/openexr/"
          '';
        }
      ];

    meta = {
      description = "High-dynamic-range image libraries, codecs, and conversion tools";
      homepage = "https://openexr.com/";
      license = "BSD-3-Clause";
    };
  }
