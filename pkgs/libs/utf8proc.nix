##! utf8proc — UTF-8 Unicode processing library
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "2.11.3";
in
  mkDerivation {
    pname = "utf8proc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-q/7VC21NpRNFcTZhNwKQ9PR0cmPuc9yQNWKZ38eZDHg=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd utf8proc-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DBUILD_SHARED_LIBS=ON \
            -DUTF8PROC_ENABLE_TESTING=ON
        '';
      }
      {
        name = "build";
        script = ''ninja -C build -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''ninja -C build test'';
      }
      {
        name = "install";
        script = ''ninja -C build install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-utf8proc";
        library = self;
        libs = ["-lutf8proc"];
        testSource = ''
          #include <stdio.h>
          #include <utf8proc.h>

          int main(void) {
              printf("%s\n", utf8proc_version());
              return utf8proc_codepoint_valid(0x1f642) ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "UTF-8 Unicode processing library";
      homepage = "https://juliastrings.github.io/utf8proc/";
      license = "MIT AND Unicode-3.0";
    };
  }
