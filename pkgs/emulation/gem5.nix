##! gem5 — Full-system architecture simulation source-build foundation
{
  mkDerivation,
  fetchurl,
  stdenv,
  python3-3_12,
  scons,
  pkg-config,
  protobuf,
  abseil-cpp,
  zlib,
  hdf5,
  capstone,
  gperftools,
  gcc-libs,
  patch,
  grep,
  findutils,
  sed,
  libpng,
  valgrind,
  m4,
}: let
  revision = "f5c5a6e390f55dd5984977815bf9d0bd05da6945";
  version = "25.1.0.1";
  compilerTargetPatch = ./gem5-patches/compiler-target-query.patch;
  reproducibleBuildPatch = ./gem5-patches/reproducible-build-environment.patch;
  eventBoundaryPatch = ./gem5-patches/nondraining-event-boundary.patch;
  timeBufferPatch = ./gem5-patches/time-buffer-value-initialization.patch;
  sourceManifest = builtins.toFile "gem5-source-manifest.json" (builtins.toJSON {
    schema = "crucible.gem5.source-foundation.v1";
    inherit revision version;
    upstream = "https://github.com/gem5/gem5";
    recipeSha256 = builtins.hashFile "sha256" ./gem5.nix;
    buildConfiguration = "ALL";
    patches = [
      {
        file = "compiler-target-query.patch";
        sha256 = builtins.hashFile "sha256" compilerTargetPatch;
      }
      {
        file = "reproducible-build-environment.patch";
        sha256 = builtins.hashFile "sha256" reproducibleBuildPatch;
      }
      {
        file = "nondraining-event-boundary.patch";
        sha256 = builtins.hashFile "sha256" eventBoundaryPatch;
      }
      {
        file = "time-buffer-value-initialization.patch";
        sha256 = builtins.hashFile "sha256" timeBufferPatch;
      }
    ];
    crucibleNodeProtocol = false;
    qualifiedExactCapture = false;
    qualifiedLiveBranch = false;
  });
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

    pname = "gem5";
    inherit version;
    src = fetchurl {
      urls = ["https://codeload.github.com/gem5/gem5/tar.gz/${revision}"];
      hash = "sha256-WPQcs29vcMMtHDHYEZORRYaaQDny3yT54OTY+AOQMgU=";
    };

    # The pinned embedded pybind11 predates Python 3.14's C API. AOS's
    # source-built 3.12 interpreter runs both generators and the simulator;
    # SCons is pure Python and does not introduce a second extension ABI.
    buildDeps = [python3-3_12 scons pkg-config protobuf patch grep findutils sed valgrind m4];
    runtimeDeps = [python3-3_12 protobuf abseil-cpp zlib hdf5 capstone gperftools gcc-libs libpng];
    PYTHONPATH = "${scons}/lib/python3.14/site-packages";
    PYTHON_CONFIG = "${python3-3_12}/bin/python3-config";
    PROTOC = "${protobuf}/bin/protoc";
    SOURCE_DATE_EPOCH = "1";
    PYTHONHASHSEED = "0";

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd gem5-${revision}
          patch --fuzz=0 -p1 < ${compilerTargetPatch}
          patch --fuzz=0 -p1 < ${reproducibleBuildPatch}
          patch --fuzz=0 -p1 < ${eventBoundaryPatch}
          patch --fuzz=0 -p1 < ${timeBufferPatch}
          ${findutils}/bin/find . -type f -name '*.py' \
            -exec ${sed}/bin/sed -i "1s|^#!.*python.*$|#!${python3-3_12}/bin/python3|" {} +
        '';
      }
      {
        name = "build";
        script = ''
          # SCons filters the subprocess environment. Propagate AOS's
          # dependency headers through its supported CPATH variable.
          export CPATH="$C_INCLUDE_PATH"
          ${python3-3_12}/bin/python3 -m SCons \
            --ignore-style --no-colors \
            defconfig build/ALL build_opts/ALL
          for feature in HAVE_PROTOBUF HAVE_HDF5 HAVE_CAPSTONE HAVE_PNG HAVE_VALGRIND USE_X86_ISA USE_ARM_ISA; do
            grep -qx "$feature=y" build/ALL/gem5.build/config
          done
          ${python3-3_12}/bin/python3 -m SCons \
            --ignore-style --no-colors \
            -j"$NIX_BUILD_CORES" build/ALL/gem5.opt
        '';
      }
      {
        name = "check";
        script = ''
          c++ -std=c++17 -O3 -flto -fno-strict-aliasing \
            -Isrc -Ibuild/ALL ${./_gem5/time-buffer-check.cc} \
            -o time-buffer-check
          ./time-buffer-check
          build/ALL/gem5.opt --build-info
          build/ALL/gem5.opt --outdir=package-check --dump-config=config.ini \
            configs/learning_gem5/part2/hello_goodbye.py
          test -s package-check/config.ini
          test -s package-check/stats.txt
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/gem5" "$out/share/licenses/gem5"
          cp build/ALL/gem5.opt "$out/bin/gem5"
          cp -R configs "$out/share/gem5/"
          cp LICENSE "$out/share/licenses/gem5/LICENSE"
          find ext -type f \( -iname '*license*' -o -iname '*copying*' -o -iname 'notice*' \) |
            while IFS= read -r licenseFile; do
              mkdir -p "$out/share/licenses/gem5/$(dirname "$licenseFile")"
              cp "$licenseFile" "$out/share/licenses/gem5/$licenseFile"
            done
          cp ${sourceManifest} "$out/share/gem5/source-manifest.json"
        '';
      }
    ];

    meta = {
      description = "Full-system architecture simulator with all upstream ISA/protocol models; unqualified for exact Crucible capture";
      homepage = "https://www.gem5.org/";
      license = "BSD-3-Clause";
      mainProgram = "gem5";
    };
  }
