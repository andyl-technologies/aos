##! Nix — The purely functional package manager
{
  mkDerivation,
  fetchurl,
  make,
  cmake,
  pkg-config,
  meson,
  ninja,
  python3,
  bison,
  flex,
  curl,
  openssl,
  sqlite,
  boost,
  editline,
  libsodium,
  nlohmann-json,
  toml11,
  libgit2,
  brotli,
  libarchive,
  gc,
  lowdown,
  bzip2,
  zlib,
}:

let
  version = "2.24.12";
in
mkDerivation {
  pname = "nix";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/NixOS/nix/archive/refs/tags/${version}.tar.gz"
    ];
    hash = "sha256-862Kc2J+EH5X9JFIaKzWN6oODXCmh91nGLrC0vZPUMg=";
  };

  buildDeps = [
    make
    cmake
    pkg-config
    meson
    ninja
    python3
    bison
    flex
  ];
  runtimeDeps = [
    curl
    openssl
    sqlite
    boost
    editline
    libsodium
    nlohmann-json
    toml11
    libgit2
    brotli
    libarchive
    gc
    lowdown
    bzip2
    zlib
  ];
  propagatedDeps = [ ];

  LDFLAGS = "-Wl,-rpath,$out/lib";

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd nix-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        export PYTHONPATH="${meson}/lib/python3/site-packages''${PYTHONPATH:+:$PYTHONPATH}"
        # Strip meson.build to only core libraries + nix executable
        # Remove docs, tests, perl bindings, C wrappers we don't need
        sed -i '/internal-api-docs/d' meson.build
        sed -i '/external-api-docs/d' meson.build
        sed -i '/libutil-c/d' meson.build
        sed -i '/libstore-c/d' meson.build
        sed -i '/libexpr-c/d' meson.build
        sed -i '/libmain-c/d' meson.build
        sed -i '/perl/d' meson.build
        sed -i '/nix-.*-test/d' meson.build
        sed -i '/nix-.*-tests/d' meson.build
        mkdir -p build && cd build
        meson setup .. \
          --prefix=$out \
          --buildtype=release
      '';
    }
    {
      name = "build";
      script = ''
        ninja -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        ninja install
      '';
    }
  ];

  meta = {
    description = "Nix — the purely functional package manager";
    homepage = "https://nixos.org/nix";
    license = "LGPL-2.1-or-later";
  };
}
