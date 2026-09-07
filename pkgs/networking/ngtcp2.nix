##! ngtcp2 — QUIC protocol library
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  pkg-config,
  boringssl,
  nghttp3,
}: let
  version = "1.22.1";
in
  mkDerivation {
    pname = "ngtcp2";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/ngtcp2/ngtcp2/releases/download/v${version}/ngtcp2-${version}.tar.bz2"];
      hash = "sha256-hzVHltWssZvzEMt3vgS9IgDDImWmvnyUuGMeJsjpPKQ=";
    };

    buildDeps = [cmake ninja pkg-config];
    runtimeDeps = [boringssl nghttp3];
    propagatedDeps = [nghttp3];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd ngtcp2-${version}
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
            -DENABLE_LIB_ONLY=ON \
            -DENABLE_OPENSSL=OFF \
            -DENABLE_BORINGSSL=ON \
            -DBORINGSSL_INCLUDE_DIR="${boringssl}/include" \
            -DBORINGSSL_LIBRARIES="${boringssl}/lib/libssl.a;${boringssl}/lib/libcrypto.a" \
            -DENABLE_SHARED_LIB=ON \
            -DENABLE_STATIC_LIB=ON
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
        pname = "lib-ngtcp2";
        library = self;
        libs = ["-lngtcp2"];
        testSource = ''
          #include <ngtcp2/ngtcp2.h>

          int main(void) {
              return ngtcp2_version(0) != 0 ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "QUIC protocol implementation";
      homepage = "https://github.com/ngtcp2/ngtcp2";
      license = "MIT";
    };
  }
