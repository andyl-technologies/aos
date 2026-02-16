##! Brotli — Generic-purpose lossless compression algorithm
{
  mkDerivation,
  fetchurl,
  make,
  cmake,
  ninja,
}:

let
  version = "1.1.0";
in
mkDerivation {
  pname = "brotli";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/google/brotli/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-5yCmyilCi4A/StFlNxdx9TmPq6OX7fZ3iDehhZnqE/8=";
  };

  buildDeps = [
    make
    cmake
    ninja
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd brotli-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        cmake -S . -B build -G Ninja \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=$out \
          -DCMAKE_INSTALL_LIBDIR=lib \
          -DBUILD_SHARED_LIBS=ON \
          -DBROTLI_DISABLE_TESTS=ON
      '';
    }
    {
      name = "build";
      script = ''
        ninja -C build -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        ninja -C build install
      '';
    }
  ];

  meta = {
    description = "Brotli — generic-purpose lossless compression algorithm";
    homepage = "https://github.com/google/brotli";
    license = "MIT";
  };
}
