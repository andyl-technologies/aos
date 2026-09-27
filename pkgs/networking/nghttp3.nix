##! nghttp3 — HTTP/3 and QPACK library
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  buildPackages,
  stdenv,
}: let
  version = "1.18.0";
  darwinInstallNameToolFlag =
    if stdenv.isCross && stdenv.hostPlatform.isDarwin
    then "-DCMAKE_INSTALL_NAME_TOOL=${buildPackages.llvm}/bin/llvm-install-name-tool"
    else "";
in
  mkDerivation {
    pname = "nghttp3";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/ngtcp2/nghttp3/releases/download/v${version}/nghttp3-${version}.tar.bz2"];
      hash = "sha256-yiMmaLlKXh+1S0FjLMVkc6tIImSDgUQQ72KnBilOZAI=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd nghttp3-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            ${darwinInstallNameToolFlag} \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DENABLE_SHARED_LIB=ON \
            -DENABLE_STATIC_LIB=OFF
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
        pname = "lib-nghttp3";
        library = self;
        libs = ["-lnghttp3"];
        testSource = ''
          #include <nghttp3/nghttp3.h>

          int main(void) {
              return nghttp3_version(0) != 0 ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "HTTP/3 mapping and QPACK implementation";
      homepage = "https://github.com/ngtcp2/nghttp3";
      license = "MIT";
    };
  }
