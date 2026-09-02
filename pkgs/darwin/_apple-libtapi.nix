##! Native Apple Text-Based API reader used by cctools ld64.
{
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  python3,
}: let
  revision = "fa9443738c1a18accef4244732ec6d6ee97a8133";
in
  mkDerivation {
    pname = "apple-libtapi";
    version = "1600.0.11.8";

    src = fetchurl {
      urls = [
        "https://github.com/tpoechtrager/apple-libtapi/archive/${revision}.tar.gz"
      ];
      hash = "sha256-z5OcZhqiiNp3Plms+KuRa7bDIr96vpEwwJpmvMmP3Fo=";
    };

    buildDeps = [cmake ninja python3];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd apple-libtapi-${revision}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -G Ninja -S src/llvm -B build \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DLLVM_INCLUDE_TESTS=OFF \
            -DLLVM_ENABLE_PROJECTS='tapi;clang' \
            -DTAPI_REPOSITORY_STRING=1600.0.11.8 \
            -DTAPI_FULL_VERSION=1600.0.11.8
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build clangBasic vt_gen libtapi
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install-libtapi install-tapi-headers
        '';
      }
    ];

    meta = {
      description = "Apple TAPI library for reading Darwin text-based stubs";
      license = "APSL-2.0 AND Apache-2.0 WITH LLVM-exception";
    };
  }
