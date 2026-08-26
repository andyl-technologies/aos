##! libgit2 — C implementation of the Git core methods
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  openssl,
  zlib,
  python3,
  libssh2,
  stdenv,
}: let
  version = "1.9.2";
in
  mkDerivation {
    pname = "libgit2";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/libgit2/libgit2/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-bwl8gvwG7OT0BTn7F+nUG68aWi/CaxuFYtIbibw1X+Y=";
    };

    buildDeps = [
      gnumake
      cmake
      ninja
      python3
    ];
    runtimeDeps = [
      openssl
      zlib
      libssh2
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libgit2-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Fix xdiff include priority: glibc has a deprecated regexp.h that
          # shadows libgit2's src/util/regexp.h when -isystem is used.
          # Change SYSTEM to regular includes so libgit2 headers win.
          sed -i 's/target_include_directories(xdiff SYSTEM PRIVATE/target_include_directories(xdiff PRIVATE/' deps/xdiff/CMakeLists.txt
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DBUILD_TESTS=OFF \
            -DUSE_SSH=ON \
            -DCMAKE_PREFIX_PATH=${libssh2} \
            -DUSE_HTTPS=OpenSSL \
            -DOPENSSL_ROOT_DIR=${openssl} \
            -DZLIB_LIBRARY=${zlib}/lib/libz.${stdenv.hostPlatform.sharedLibraryExtension} \
            -DZLIB_INCLUDE_DIR=${zlib}/include
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
      description = "libgit2 — C implementation of the Git core methods";
      homepage = "https://libgit2.org";
      license = "GPL-2.0-only WITH GCC-exception-3.1";
    };
  }
