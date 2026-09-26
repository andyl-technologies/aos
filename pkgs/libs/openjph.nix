##! OpenJPH — high-throughput JPEG 2000 codec and command-line tools.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  libtiff,
}: let
  version = "0.32.0";
  imageFixtureScript = ''
    from pathlib import Path

    pixels = bytes(
        (x * 7 + y * 13 + channel * 53) % 256
        for y in range(64)
        for x in range(64)
        for channel in range(3)
    )
    Path("input.ppm").write_bytes(b"P6\n64 64\n255\n" + pixels)
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
    pname = "openjph";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A deterministic 64-by-64 RGB bitmap.";
        operation = "Encode it as a reversible JPEG 2000 codestream and expand it.";
        expected = "The decoded pixels exactly match the input bitmap.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@python@" "-c" imageFixtureScript];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/ojph_compress" "-i" "input.ppm" "-o" "lossless.j2c" "-reversible" "true"];
            exit_code = 0;
          }
          {
            argv = ["@out@/bin/ojph_expand" "-i" "lossless.j2c" "-o" "output.ppm"];
            exit_code = 0;
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                assert Path("input.ppm").read_bytes() == Path("output.ppm").read_bytes()
                print("OpenJPH image round trip passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "OpenJPH image round trip passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Bytes that are not a JPEG 2000 codestream.";
        operation = "Attempt to expand the invalid codestream.";
        expected = "The decoder rejects the invalid image.";
        files."bad.j2c" = "not JPEG 2000\n";
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess

                result = subprocess.run(
                    ["@out@/bin/ojph_expand", "-i", "bad.j2c", "-o", "bad.ppm"],
                    capture_output=True,
                )
                assert result.returncode != 0
                print("OpenJPH rejected invalid input")
              ''
            ];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "OpenJPH rejected invalid input\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/aous72/OpenJPH/archive/refs/tags/${version}.tar.gz"];
      hash = "06gp62pf6jzqdk8w71jmmp8lgm32fnrk08gz4cnk5qayivhypcaw";
    };

    buildDeps = [buildPackages.cmake buildPackages.gnumake buildPackages.pkg-config buildPackages.python3];
    runtimeDeps = [libtiff];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd OpenJPH-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build-aos $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=${libtiff} \
              -DOJPH_ENABLE_TIFF_SUPPORT=ON
          '';
        }
        {
          name = "build";
          script = ''
            cmake --build build-aos --parallel "$NIX_BUILD_CORES"
          '';
        }
        {
          name = "install";
          script = ''
            cmake --install build-aos
            mkdir -p "$out/share/licenses/openjph"
            cp LICENSE "$out/share/licenses/openjph/"
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
              ${buildPackages.python3}/bin/python3 -c ${lib.escapeShellArg imageFixtureScript}
              "$out/bin/ojph_compress" -i input.ppm -o lossless.j2c -reversible true
              "$out/bin/ojph_expand" -i lossless.j2c -o output.ppm
              cmp input.ppm output.ppm
            '';
          }
        ]
      );

    meta = {
      description = "HTJ2K image codec library and compression tools";
      homepage = "https://github.com/aous72/OpenJPH";
      license = "BSD-2-Clause";
    };
  }
