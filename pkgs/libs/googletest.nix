##! GoogleTest — C++ testing and mocking libraries.
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "1.17.0";
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
      ];
      target = [];
      role = "public-package";
    };
    pname = "googletest";
    qualification.packageProbe = lib.qualification.commandProbe (let
      source = ''
        #include <gtest/gtest.h>

        TEST(Assertions, Equal) { ASSERT_EQ(42, 42); }
        TEST(Assertions, Unequal) { ASSERT_EQ(41, 42); }

        int main(int argc, char **argv) {
            testing::InitGoogleTest(&argc, argv);
            return RUN_ALL_TESTS();
        }
      '';
      compile = {
        argv = ["@cxx@" "probe.cpp" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib" "-lgtest" "-pthread" "-o" "probe"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      };
    in {
      primary = {
        input = "Two equal integer values.";
        operation = "Compile a consumer and run the equal-value assertion.";
        expected = "The test runner reports success.";
        files."probe.cpp" = source;
        artifacts = [];
        steps = [
          compile
          {
            argv = ["@work@/primary/probe" "--gtest_filter=Assertions.Equal"];
            exit_code = 0;
          }
        ];
      };
      badInput = {
        input = "Two different integer values.";
        operation = "Run the unequal-value assertion.";
        expected = "The test runner records failure and returns a failing status.";
        files."probe.cpp" = source;
        artifacts = [];
        steps = [
          compile
          {
            argv = ["@work@/bad-input/probe" "--gtest_filter=Assertions.Unequal"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
      };
    });
    version = "=${version}";

    src = fetchurl {
      urls = [
        "https://github.com/google/googletest/archive/refs/tags/v${version}.tar.gz"
        "https://codeload.github.com/google/googletest/tar.gz/refs/tags/v${version}"
      ];
      hash = "sha256-Zfq3AdmCnTjLd8FKzcQx0hCL/b+JeeQOuK5Wft8Qsnw=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd googletest-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=ON \
            -Dgtest_build_tests=ON \
            -Dgmock_build_tests=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel "$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          ctest --test-dir build --output-on-failure --parallel "$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
          mkdir -p "$out/share/licenses/googletest"
          cp LICENSE "$out/share/licenses/googletest/"
        '';
      }
    ];

    meta = {
      description = "C++ testing and mocking framework";
      homepage = "https://github.com/google/googletest";
      license = "BSD-3-Clause";
    };
  }
