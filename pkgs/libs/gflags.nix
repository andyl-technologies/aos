##! Thread-safe command-line flag parsing for native applications.
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
}: let
  version = "2.3.0";
  consumerSource = ''
    #include <cstdio>
    #include <string>
    #include <gflags/gflags.h>

    DEFINE_int32(count, 0, "Item count");

    int main(int argc, char**) {
        const bool reject = argc > 1;
        const std::string result = gflags::SetCommandLineOption(
            "count", reject ? "invalid" : "42");
        if (reject) {
            if (!result.empty() || FLAGS_count != 0) return 2;
            std::fputs("gflags rejected invalid input\n", stderr);
            return 7;
        }
        if (result.empty() || FLAGS_count != 42) return 2;
        return std::puts("gflags api passed") == EOF;
    }
  '';
  probe = reject: {
    input =
      if reject
      then "A nonnumeric value for the integer flag."
      else "A declared integer flag and a decimal value.";
    operation =
      if reject
      then "Set an invalid integer value and confirm that the existing value is retained."
      else "Set the declared flag through SetCommandLineOption and inspect its value.";
    expected =
      if reject
      then "The library rejects the invalid input."
      else "The public API returns the expected value.";
    files."consumer.cc" = consumerSource;
    artifacts = [];
    steps = [
      {
        argv =
          ["@cxx@" "consumer.cc" "-std=c++20" "-g" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"]
          ++ ["-lgflags"]
          ++ ["-o" "consumer"];
        exit_code = 0;
        stdout.exact = "";
      }
      ({
          argv =
            [
              "@work@/${
                if reject
                then "bad-input"
                else "primary"
              }/consumer"
            ]
            ++ (
              if reject
              then ["reject"]
              else []
            );
          exit_code =
            if reject
            then 7
            else 0;
          observes_rejection = reject;
          stdout.exact =
            if reject
            then ""
            else "gflags api passed\n";
        }
        // (
          if reject
          then {stderr.exact = "gflags rejected invalid input\n";}
          else {}
        ))
    ];
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
      ];
      target = [];
      role = "public-package";
    };
    pname = "gflags";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = probe false;
      badInput = probe true;
    };
    version = "=${version}";

    src = fetchurl {
      urls = ["https://github.com/gflags/gflags/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-9hmlE3H0HArWg3sqmK+dRkOzNxAV2HOIf36NMjcyCy8=";
    };

    buildDeps = [cmake gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gflags-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=ON \
            -DBUILD_STATIC_LIBS=ON \
            -DBUILD_gflags_LIB=ON \
            -DGFLAGS_BUILD_TESTING=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel $NIX_BUILD_CORES
        '';
      }
      {
        name = "check";
        script = ''
          ctest --test-dir build --output-on-failure
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
        '';
      }
    ];

    meta = {
      description = "Thread-safe command-line flag parsing library";
      homepage = "https://gflags.github.io/gflags/";
      license = "BSD-3-Clause";
    };
  }
