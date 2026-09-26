##! OpenEXR — high-dynamic-range image libraries and tools.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  imath,
  libdeflate,
  openjph,
}: let
  version = "3.4.15";
  # A two-by-two scanline image written by this package's RgbaOutputFile API.
  imageFixtureBase85 = "b}umj0ssI2V`yP+Ze?t90ApxuX>)V{NdN!<K>z^&000000003100031002S&0RR91000000RR910RR91M*sl;000000003100031002?|0RR91000000RR910RR910Ap`$aB^jHb7^mG0Ap`$aB^jHb7^mG0096100d-VbYWL%Ze(wF0Ag==GHC!1000000000000001000010001FX>)LFVR=_+Ze(wF0Ag==GHC!1000000000000001000010001NX>Mgta%5$40BmV)WlwTsWpV%k00000aA|mDY(aByWn*+wVRUJ40A_4&VRQfl000000DwPpV{&C>ZdYk;WN&vvWo~q3asYNRW&j8P00000000000047ia%E+1S7~l!Z+BN|WOQf%W^8X^bN~bZ00000fIk3J0RR91000000000W00000JODfZ00000002AyJOBUyJODfZJODfZ002Ay002A";
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
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A two-by-two OpenEXR image with four half-float channels.";
        operation = "Validate the image and inspect its declared pixel window and channels.";
        expected = "The image validates and reports the expected dimensions and RGBA channels.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import base64
                from pathlib import Path

                Path("input.exr").write_bytes(base64.b85decode("${imageFixtureBase85}"))
              ''
            ];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/exrcheck" "-c" "input.exr"];
            exit_code = 0;
            stdout.exact = " file input.exr OK\n";
            stderr.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess

                result = subprocess.run(
                    ["@out@/bin/exrheader", "input.exr"],
                    capture_output=True,
                    text=True,
                )
                assert result.returncode == 0, result.stderr
                assert "dataWindow (type box2i): (0 0) - (1 1)" in result.stdout
                for channel in ("A", "B", "G", "R"):
                    assert f"    {channel}, 16-bit floating-point" in result.stdout
                print("OpenEXR image inspection passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "OpenEXR image inspection passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Bytes that are not an OpenEXR image.";
        operation = "Validate the malformed image.";
        expected = "The validator rejects the invalid image.";
        files."bad.exr" = "not an EXR\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/exrcheck" "-c" "bad.exr"];
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = " file bad.exr bad\n";
            stderr.exact = "";
          }
        ];
      };
    };
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
