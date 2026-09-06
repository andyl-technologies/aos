##! libuv — Portable asynchronous I/O library
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "1.52.1";
in
  mkDerivation {
    pname = "libuv";
    inherit version;

    src = fetchurl {
      urls = [
        "https://dist.libuv.org/dist/v${version}/libuv-v${version}.tar.gz"
      ];
      hash = "sha256-ZtURuebjNMDmInnrI0+/srMRCxR5wJuVtEx6/KjP+ec=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libuv-v${version}
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
            -DBUILD_TESTING=OFF \
            -DLIBUV_BUILD_SHARED=ON \
            -DLIBUV_BUILD_TESTS=OFF \
            -DLIBUV_BUILD_BENCH=OFF
        '';
      }
      {
        name = "build";
        script = ''ninja -C build -j"$NIX_BUILD_CORES"'';
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
        pname = "lib-libuv";
        library = self;
        libs = ["-luv"];
        testSource = ''
          #include <uv.h>
          #include <stdio.h>

          int main(void) {
              printf("%s\n", uv_version_string());
              return uv_version() == 0 ? 1 : 0;
          }
        '';
      };
    };

    meta = {
      description = "Portable asynchronous I/O library";
      homepage = "https://libuv.org/";
      license = "MIT AND ISC AND BSD-2-Clause AND BSD-3-Clause AND CC-BY-4.0";
    };
  }
