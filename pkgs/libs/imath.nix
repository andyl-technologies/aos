##! Imath — vector, matrix, and half-precision arithmetic for imaging.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "3.2.3";
  probeSource = ''
    #include <cstdio>
    #include <stdexcept>
    #include <string_view>
    #include <Imath/ImathMatrix.h>
    #include <Imath/half.h>

    int main(int argc, char **argv) {
        if (argc > 1 && std::string_view(argv[1]) == "bad") {
            Imath::M44f singular(0.0f);
            try {
                singular.inverse(true);
            } catch (const std::invalid_argument &) {
                std::puts("imath rejected singular matrix");
                return 0;
            }
            return 2;
        }

        Imath::M44f matrix;
        matrix.makeIdentity();
        matrix[0][0] = 2.0f;
        Imath::M44f inverse = matrix.inverse(true);
        Imath::half value(1.5f);
        if (inverse[0][0] != 0.5f || float(value) != 1.5f) return 3;
        std::puts("imath matrix and half arithmetic passed");
        return 0;
    }
  '';
  compileProbe = {
    argv = [
      "@cxx@"
      "-std=c++17"
      "-I@out@/include"
      "probe.cpp"
      "-L@out@/lib"
      "-Wl,-rpath,@out@/lib"
      "-lImath-3_2"
      "-o"
      "probe"
    ];
    exit_code = 0;
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
    pname = "imath";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "An invertible matrix and a half-precision number.";
        operation = "Invert the matrix and convert the half value through Imath.";
        expected = "The inverse and converted value match their known results.";
        files."probe.cpp" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["./probe"];
            exit_code = 0;
            stdout.exact = "imath matrix and half arithmetic passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A singular zero matrix.";
        operation = "Request its inverse with singularity checking enabled.";
        expected = "Imath rejects the inverse with invalid_argument.";
        files."probe.cpp" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["./probe" "bad"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "imath rejected singular matrix\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/AcademySoftwareFoundation/Imath/archive/refs/tags/v${version}.tar.gz"];
      hash = "1y7r5pnyyvqbvr0disxy8zbnh4v9qzciahlxw04byi8zyari4371";
    };

    buildDeps = [buildPackages.cmake buildPackages.gnumake];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd Imath-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
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
            mkdir -p "$out/share/licenses/imath"
            cp LICENSE.md "$out/share/licenses/imath/"
          '';
        }
      ];

    meta = {
      description = "Vector, matrix, and half-precision arithmetic library";
      homepage = "https://imath.readthedocs.io/";
      license = "BSD-3-Clause";
    };
  }
