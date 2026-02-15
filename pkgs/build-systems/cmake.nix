##! cmake — cross-platform build system generator
{
  mkDerivation,
  fetchurl,
  make,
  openssl,
  zlib,
}:

let
  version = "3.31.4";
in
mkDerivation {
  pname = "cmake";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/Kitware/CMake/releases/download/v${version}/cmake-${version}.tar.gz"
    ];
    hash = "sha256-phML/nX1ulxz5nLjQ1n3wKGTFSGVfoOTpcKSLIsPfyU=";
  };

  buildDeps = [ make ];
  runtimeDeps = [
    openssl
    zlib
  ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd cmake-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./bootstrap \
          --prefix=$out \
          --parallel=$NIX_BUILD_CORES \
          --system-zlib \
          -- \
          -DCMAKE_USE_OPENSSL=ON \
          -DZLIB_LIBRARY=${zlib}/lib/libz.so \
          -DZLIB_INCLUDE_DIR=${zlib}/include \
          -DOPENSSL_ROOT_DIR=${openssl} \
          -DOPENSSL_CRYPTO_LIBRARY=${openssl}/lib/libcrypto.so \
          -DOPENSSL_SSL_LIBRARY=${openssl}/lib/libssl.so \
          -DOPENSSL_INCLUDE_DIR=${openssl}/include
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        make install
      '';
    }
  ];

  meta = {
    description = "Cross-platform build system generator";
    homepage = "https://cmake.org";
    license = "BSD-3-Clause";
  };
}
