##! libdeflate — Optimized DEFLATE, zlib, and gzip compression.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  zlib,
  lib,
}: let
  version = "1.26";
  src = fetchurl {
    urls = ["https://github.com/ebiggers/libdeflate/archive/refs/tags/v${version}.tar.gz"];
    hash = "11fg2fgmzl52pvzdbr42gpkf4v7zzil6kkkm6qhpd1akqpzkz85v";
  };
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
    pname = "libdeflate";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A short text message passed through the installed compressor.";
        operation = "Compress with libdeflate-gzip and decompress with libdeflate-gunzip.";
        expected = "The round trip reproduces the exact input bytes.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''                import subprocess, sys
                payload = b"AOS libdeflate roundtrip\n"
                compressed = subprocess.run([sys.argv[1], "-c"], input=payload, capture_output=True, check=True)
                restored = subprocess.run([sys.argv[2], "-c"], input=compressed.stdout, capture_output=True, check=True)
                assert restored.stdout == payload
                print("libdeflate roundtrip passed")
              ''
              "@out@/bin/libdeflate-gzip"
              "@out@/bin/libdeflate-gunzip"
            ];
            exit_code = 0;
            stdout.exact = "libdeflate roundtrip passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Bytes without a gzip header.";
        operation = "Decompress malformed input with the installed utility.";
        expected = "The decompressor rejects the malformed stream.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/libdeflate-gunzip" "-c"];
            stdin = "invalid gzip";
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "libdeflate-gunzip: standard input: not in gzip format\n";
          }
        ];
      };
    };
    inherit version src;

    buildDeps = [buildPackages.cmake buildPackages.gnumake];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libdeflate-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -DCMAKE_PREFIX_PATH="${zlib}" \
              -DCMAKE_BUILD_RPATH="${zlib}/lib" \
              -DLIBDEFLATE_BUILD_TESTS=ON
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
            mkdir -p "$out/share/licenses/libdeflate"
            cp COPYING "$out/share/licenses/libdeflate/"
          '';
        }
      ];

    meta = {
      description = "DEFLATE, zlib, and gzip compression library and command-line tools";
      homepage = "https://github.com/ebiggers/libdeflate";
      license = "MIT";
    };
  }
