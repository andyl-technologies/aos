##! BoringSSL — Google TLS implementation for private static linking
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  perl,
}: let
  version = "0.20260803.0";
in
  mkDerivation {
    pname = "boringssl";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/google/boringssl/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-WFyReC/AZRum8jdrZyrNwwQ3cF2KULSWfCDmKT4xiWk=";
    };

    buildDeps = [cmake ninja perl];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd boringssl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
            -DBUILD_SHARED_LIBS=OFF
        '';
      }
      {
        name = "build";
        script = ''ninja -C build -j"$NIX_BUILD_CORES" crypto ssl bssl'';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/include" "$out/lib"
          cp build/bssl "$out/bin/"
          cp build/libcrypto.a build/libssl.a "$out/lib/"
          cp -R include/openssl "$out/include/"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-boringssl";
        tool = self;
        command = "bssl ciphers DEFAULT >/dev/null";
      };
    };

    meta = {
      description = "TLS implementation for private static linking";
      homepage = "https://boringssl.googlesource.com/boringssl/";
      license = "Apache-2.0 AND ISC AND MIT AND BSD-3-Clause";
      mainProgram = "bssl";
    };
  }
