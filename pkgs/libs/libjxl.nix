##! JPEG XL image codecs and command-line tools.
{
  mkDerivation,
  callPackage,
  fetchurl,
  buildPackages,
  stdenv,
  highway,
  brotli,
  lcms2,
  libpng,
  zlib,
  mozjpeg,
  openexr,
  imath,
  openjdk,
}: let
  needsAssembler = !stdenv.isCross && stdenv.hostPlatform.isLinux && stdenv.hostPlatform.isx86_64;
  assembler = import ./_highway-assembler.nix {inherit buildPackages fetchurl;};
  sources = callPackage ./_libjxl-sources.nix {};
  # The tools link Imath directly through OpenEXR's imported CMake targets.
  # Retain its runtime path as a direct dependency of the installed tools.
  dependencies = [highway brotli lcms2 libpng zlib mozjpeg openexr imath];
in
  mkDerivation {
    pname = "libjxl";
    inherit (sources) version src;
    passthru.evidenceSources = [sources.src sources.skcms sources.sjpeg sources.googletest sources.testdata];

    buildDeps = [buildPackages.cmake buildPackages.gnumake buildPackages.pkg-config buildPackages.python3 buildPackages.asciidoc buildPackages.doxygen buildPackages.graphviz buildPackages.git buildPackages.openjdk openjdk];
    runtimeDeps = dependencies;
    propagatedDeps = [highway brotli lcms2];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libjxl-${sources.version}
            # GitHub release archives omit gitlinks. Restore their exact source
            # revisions, including the test fixtures paired with this release.
            tar xf ${sources.skcms} --strip-components=1 -C third_party/skcms
            tar xf ${sources.sjpeg} --strip-components=1 -C third_party/sjpeg
            tar xf ${sources.googletest} --strip-components=1 -C third_party/googletest
            tar xf ${sources.testdata} --strip-components=1 -C testdata
          '';
        }
        {
          name = "configure";
          script = ''
            ${
              if needsAssembler
              then ''
                # GCC's Highway dispatch targets include AVX10.2, which the
                # bootstrap assembler predates. Preserve the wrapper's libc,
                # linker, and hardening flags while preferring the newer as.
                mkdir compiler
                for language in CC CXX; do
                  eval "compiler=\$$language"
                  sed 's| -B| -B${assembler}/bin/ -B|' "$compiler" > "compiler/$language"
                  chmod +x "compiler/$language"
                done
                export CC="$PWD/compiler/CC" CXX="$PWD/compiler/CXX"
              ''
              else ""
            }
            cmake -S . -B build $cmakeFlags \
              -DJAVA_HOME=${openjdk} \
              -DJava_JAVA_EXECUTABLE=${buildPackages.openjdk}/bin/java \
              -DJava_JAVAC_EXECUTABLE=${buildPackages.openjdk}/bin/javac \
              -DJava_JAR_EXECUTABLE=${buildPackages.openjdk}/bin/jar \
              -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_PREFIX_PATH="${builtins.concatStringsSep ";" (map toString dependencies)}" \
              -DJPEGXL_FORCE_SYSTEM_BROTLI=ON -DJPEGXL_FORCE_SYSTEM_HWY=ON \
              -DJPEGXL_FORCE_SYSTEM_LCMS2=ON -DBUILD_TESTING=ON \
              -DFETCHCONTENT_FULLY_DISCONNECTED=ON
          '';
        }
        {
          name = "build";
          script = ''
            cmake --build build --parallel "$NIX_BUILD_CORES"
            # Upstream defines API documentation as a separate, non-default target.
            if ! cmake --build build --target doc --parallel "$NIX_BUILD_CORES" > documentation.log 2>&1; then
              cat documentation.log
              exit 1
            fi
            cat documentation.log
            # Doxygen can exit successfully after a renderer fails. Do not
            # install HTML with missing diagrams merely because its exit is zero.
            if grep -Eq '(^|[[:space:]])error:' documentation.log; then
              exit 1
            fi
            test -s build/doc/html/graph_legend.png
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
            mkdir -p "$out/share/doc/libjxl"
            cp -R build/doc/html build/doc/xml "$out/share/doc/libjxl/"
            mkdir -p "$out/share/licenses/libjxl"
            cp LICENSE PATENTS "$out/share/licenses/libjxl/"
            cp third_party/skcms/LICENSE "$out/share/licenses/libjxl/LICENSE.skcms"
            cp third_party/sjpeg/COPYING "$out/share/licenses/libjxl/LICENSE.sjpeg"
          '';
        }
      ];

    meta = {
      description = "JPEG XL encoding, decoding, and image conversion tools";
      homepage = "https://jpeg.org/jpegxl/";
      license = "BSD-3-Clause";
    };
  }
