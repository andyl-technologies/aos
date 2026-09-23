##! Ultra HDR JPEG support matching Sharp's image codec configuration.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  mozjpeg,
}: let
  version = "2.0.2";
  googletest = fetchurl {
    urls = ["https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz"];
    hash = "1mx5pc0nb2lkaw0cglrwwxrhsqrav3mjq20b53cf15np7b3rimca";
  };
  platformPatch = fetchurl {
    urls = ["https://patch-diff.githubusercontent.com/raw/google/libultrahdr/pull/383.patch"];
    hash = "1fj9nxpmgj4vxykb648b6n641ymw47dh2fsibrsn9s8sl6r8srap";
  };
in
  mkDerivation {
    pname = "sharp-ultrahdr";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/google/libultrahdr/archive/v${version}.tar.gz"];
      hash = "0b7gy5y57j407xnjp0gqgbhg8x5k0gfi21bq3724ihw7p0xik3da";
    };
    buildDeps = [buildPackages.cmake buildPackages.gnumake buildPackages.pkg-config buildPackages.python3];
    runtimeDeps = [mozjpeg];
    passthru.evidenceSources = [googletest platformPatch];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libultrahdr-${version}
            patch -p1 < ${platformPatch}
            mkdir -p third_party/googletest
            tar xf ${googletest} --strip-components=1 -C third_party/googletest
            ${buildPackages.python3}/bin/python3 - <<'PY'
            from pathlib import Path
            path = Path('CMakeLists.txt')
            text = path.read_text()
            old = 'GIT_REPOSITORY https://github.com/google/googletest\n      GIT_TAG v1.14.0'
            assert old in text
            text = text.replace(old, 'DOWNLOAD_COMMAND ""\n      UPDATE_COMMAND ""')
            # Installation is valid with the AOS cross toolchain and target prefix.
            text = text.replace('if(CMAKE_CROSSCOMPILING AND UHDR_ENABLE_INSTALL)', 'if(FALSE)')
            path.write_text(text)
            PY
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
              -DJPEG_LIBRARY=${mozjpeg}/lib/libjpeg.so -DJPEG_INCLUDE_DIR=${mozjpeg}/include \
              -DUHDR_BUILD_TESTS=ON -DUHDR_BUILD_DEPS=OFF \
              -DUHDR_ENABLE_HEIF=OFF -DUHDR_MAX_DIMENSION=65500
          '';
        }
        {
          name = "build";
          script = ''cmake --build build --parallel "$NIX_BUILD_CORES"'';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''ctest --test-dir build --output-on-failure'';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            cmake --install build
            mkdir -p "$out/share/licenses/sharp-ultrahdr"
            cp -R LICENSE LICENSE-APACHE LICENSE-MIT adobe-hdr-gain-map-license "$out/share/licenses/sharp-ultrahdr/"
            find third_party -type f \( -iname '*license*' -o -iname '*copying*' -o -iname '*notice*' \) \
              -exec cp --parents '{}' "$out/share/licenses/sharp-ultrahdr/" \;
          '';
        }
      ];
    meta = {
      description = "Ultra HDR JPEG codec for Sharp";
      homepage = "https://github.com/google/libultrahdr";
      license = "Apache-2.0 OR MIT";
    };
  }
