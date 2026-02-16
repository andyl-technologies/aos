##! toml11 — TOML for Modern C++ (header-only)
{
  mkDerivation,
  fetchurl,
  make,
  cmake,
  ninja,
}:

let
  version = "4.2.0";
in
mkDerivation {
  pname = "toml11";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/ToruNiina/toml11/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-koeXHNSho5ku8357laOXLRrlZBDn+OPzAHJ6sdbHnCw=";
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
        cd toml11-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        cmake -S . -B build -G Ninja \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=$out \
          -DCMAKE_INSTALL_LIBDIR=lib \
          -Dtoml11_BUILD_TEST=OFF \
          -Dtoml11_BUILD_EXAMPLES=OFF
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
    description = "toml11 — TOML for Modern C++ (header-only)";
    homepage = "https://github.com/ToruNiina/toml11";
    license = "MIT";
  };
}
