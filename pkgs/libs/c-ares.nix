##! c-ares — Asynchronous DNS request library
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
}: let
  version = "1.34.8";
in
  mkDerivation {
    pname = "c-ares";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/c-ares/c-ares/releases/download/v${version}/c-ares-${version}.tar.gz"
      ];
      hash = "sha256-wiK21oEJb5RE0sSGPSwRdAGeJ8rMoKSlwRTTbdfXv3g=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd c-ares-${version}
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
            -DCARES_SHARED=ON \
            -DCARES_STATIC=ON \
            -DCARES_BUILD_TOOLS=ON \
            -DCARES_BUILD_TESTS=OFF
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
        pname = "lib-c-ares";
        library = self;
        libs = ["-lcares"];
        testSource = ''
          #include <ares.h>

          int main(void) {
              return ares_library_init(ARES_LIB_INIT_ALL);
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-c-ares";
        tool = self;
        command = "adig --help >/dev/null";
      };
    };

    meta = {
      description = "Asynchronous DNS request library";
      homepage = "https://c-ares.org/";
      license = "MIT";
    };
  }
