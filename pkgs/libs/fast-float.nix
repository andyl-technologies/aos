##! Locale-independent floating-point parsing for C++.
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
}: let
  version = "8.0.0";
  consumerSource = ''
    #include <cstdio>
    #include <cstring>
    #include <system_error>
    #include <fast_float/fast_float.h>

    int main(int argc, char**) {
        const bool reject = argc > 1;
        const char* input = reject ? "invalid" : "42.5";
        double value = 0;
        const auto result = fast_float::from_chars(input, input + std::strlen(input), value);
        if (reject) {
            if (result.ec != std::errc::invalid_argument || result.ptr != input) return 2;
            std::fputs("fast-float rejected invalid input\n", stderr);
            return 7;
        }
        if (result.ec != std::errc{} || value != 42.5) return 2;
        return std::puts("fast-float api passed") == EOF;
    }
  '';
  probe = reject: {
    input =
      if reject
      then "A nonnumeric string."
      else "A decimal floating-point value.";
    operation =
      if reject
      then "Confirm from_chars returns invalid_argument without consuming input."
      else "Parse the decimal through fast_float::from_chars and compare the value.";
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
          ++ []
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
            else "fast-float api passed\n";
        }
        // (
          if reject
          then {stderr.exact = "fast-float rejected invalid input\n";}
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
    pname = "fast-float";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = probe false;
      badInput = probe true;
    };
    version = "=${version}";

    src = fetchurl {
      urls = ["https://github.com/fastfloat/fast_float/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-8xLy3DTGHmZfSxMsAwfW9wrZQgGF+oMZEbwkQIrPYl0=";
    };

    buildDeps = [cmake gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd fast_float-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DFASTFLOAT_TEST=OFF
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
      description = "Header-only locale-independent floating-point parsing";
      homepage = "https://github.com/fastfloat/fast_float";
      license = "MIT OR Apache-2.0 OR BSL-1.0";
    };
  }
