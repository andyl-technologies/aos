##! Folly's native utility libraries, built with the complete Linux dependency set.
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
  gcc-libs,
  stdenv,
  boost,
  fast-float,
  fmt,
  gflags,
  glog,
  libevent,
  openssl,
  zlib,
  bzip2,
  xz,
  lz4,
  zstd,
  snappy,
  libdwarf,
  libiberty,
  libaio,
  liburing,
  libsodium,
  libunwind,
}: let
  version = "2026.10.9";
  revision = "7ba92f0e29d24b453cee8ab27d117b1c7cc19589";
  dependencies = [
    gcc-libs
    boost
    boost.dev
    fast-float
    fmt
    gflags
    glog
    libevent
    openssl
    zlib
    bzip2
    xz
    lz4
    zstd
    snappy
    libdwarf
    libiberty
    libaio
    liburing
    libsodium
    libunwind
  ];
  consumerSource = ''
    #include <cstdio>
    #include <stdexcept>
    #include <folly/Conv.h>

    int main(int argc, char**) {
        if (argc > 1) {
            try {
                static_cast<void>(folly::to<int>("invalid"));
            } catch (const std::exception&) {
                std::fputs("folly rejected invalid input\n", stderr);
                return 7;
            }
            return 2;
        }
        if (folly::to<int>("42") != 42) return 2;
        return std::puts("folly api passed") == EOF;
    }
  '';
  probe = reject: {
    input =
      if reject
      then "A nonnumeric string."
      else "A decimal integer string.";
    operation =
      if reject
      then "Confirm folly::to<int> rejects the string with an exception."
      else "Convert the string through folly::to<int> and compare the result.";
    expected =
      if reject
      then "The library rejects the invalid input."
      else "The public API returns the expected value.";
    files."consumer.cc" = consumerSource;
    artifacts = [];
    steps = [
      {
        argv =
          ["@cxx@" "consumer.cc" "-std=c++20" "-g" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"]
          ++ (map (dependency: "-I${builtins.unsafeDiscardStringContext (toString dependency)}/include") dependencies)
          ++ ["-L${builtins.unsafeDiscardStringContext (toString gcc-libs)}/lib" "-Wl,-rpath,${builtins.unsafeDiscardStringContext (toString gcc-libs)}/lib" "-lfolly"]
          ++ ["-o" "consumer"];
        exit_code = 0;
        stdout.exact = "";
      }
      ({
          argv =
            [
              "@work@/${
                if reject
                then "bad-input"
                else "primary"
              }/consumer"
            ]
            ++ (
              if reject
              then ["reject"]
              else []
            );
          exit_code =
            if reject
            then 7
            else 0;
          observes_rejection = reject;
          stdout.exact =
            if reject
            then ""
            else "folly api passed\n";
        }
        // (
          if reject
          then {stderr.exact = "folly rejected invalid input\n";}
          else {}
        ))
    ];
  };
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "folly";
    cacheCCompilers = true;
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = probe false;
      badInput = probe true;
    };
    version = "=${version}";

    src = fetchurl {
      urls = ["https://github.com/facebook/folly/archive/${revision}.tar.gz"];
      hash = "sha256-IFyY4ybdypi4n0Kzl2hAHorxKRK/OctF5lZmfLXsldM=";
    };

    buildDeps = [cmake gnumake];
    runtimeDeps = dependencies;
    propagatedDeps = dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd folly-${revision}
          patch -p1 < ${./folly-openssl-4.patch}
        '';
      }
      {
        name = "configure";
        script = ''
          # Dependency discovery must consume only the package closure. Missing
          # dependencies fail configuration rather than downloading at build time.
          # Exception tracing interposes the shared C++ runtime; the compiler
          # archive alone cannot supply that dynamic symbol boundary.
          cmake -S . -B build $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DBacktrace_INCLUDE_DIR=${stdenv.glibc.dev}/include \
            -DCMAKE_PREFIX_PATH="${lib.concatStringsSep ";" dependencies}" \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_SHARED_LINKER_FLAGS="-L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib" \
            -DCMAKE_EXE_LINKER_FLAGS="-L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib" \
            -DBUILD_SHARED_LIBS=ON \
            -DBOOST_LINK_STATIC=OFF \
            -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
            -DFETCHCONTENT_UPDATES_DISCONNECTED=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel $NIX_BUILD_CORES
        '';
      }
      {
        name = "check";
        script = ''
          cat > folly-consumer.cc <<'CPP'
          ${consumerSource}
          CPP
          $CXX -std=c++20 -I. -Ibuild folly-consumer.cc \
            -Lbuild -Wl,-rpath,$PWD/build \
            -L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib -lfolly -o folly-consumer
          ./folly-consumer

          # Conversion errors must stay observable through the public API.
          status=0
          ./folly-consumer reject || status=$?
          test "$status" -eq 7

          $CXX -std=c++20 -I. -Ibuild ${./_folly-openssl-check.cc} \
            -Lbuild -Wl,-rpath,$PWD/build \
            -L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib -lfolly -lcrypto -o folly-openssl-check
          ./folly-openssl-check
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
          mkdir -p $out/share/licenses/folly
          cp LICENSE $out/share/licenses/folly/
        '';
      }
    ];

    meta = {
      description = "Native utility libraries for high-performance applications";
      homepage = "https://github.com/facebook/folly";
      license = "Apache-2.0";
    };
  }
