##! libaec — Adaptive entropy coding and SZIP compatibility libraries
{
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
  buildPackages,
  stdenv,
}: let
  version = "1.1.4";
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

    pname = "libaec";
    inherit version;
    src = fetchurl {
      urls = ["https://codeload.github.com/Deutsches-Klimarechenzentrum/libaec/tar.gz/refs/tags/v${version}"];
      hash = "sha256-emQySjf3X5bKjg9tGtnRMFewE7taBSmMQ0afZHakAjI=";
    };

    buildDeps = [cmake gnumake buildMake];
    runtimeDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libaec-${version}
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
            -DBUILD_TESTING=ON
        '';
      }
      {
        name = "build";
        script = ''cmake --build build --parallel "$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''ctest --test-dir build --output-on-failure --no-tests=error'';
      }
      {
        name = "install";
        script = ''
          cmake --install build
          mkdir -p "$out/share/licenses/libaec"
          cp LICENSE.txt "$out/share/licenses/libaec/LICENSE.txt"
        '';
      }
    ];

    meta = {
      description = "Lossless adaptive entropy coding with SZIP-compatible encoding and decoding";
      homepage = "https://github.com/Deutsches-Klimarechenzentrum/libaec";
      license = "BSD-2-Clause";
    };
  }
