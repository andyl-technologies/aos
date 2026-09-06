##! abseil-cpp — Common C++ libraries used by Protocol Buffers
{
  mkDerivation,
  mkGithubUpstream,
  cmake,
  gnumake,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "abseil-cpp-20230802";
    family = "abseil-cpp";
    stream = "20230802";
    owner = "pkgs/libs/abseil-cpp.nix";
    classification = "assisted";
    version = "20230802.0";
    upstreamId = "20230802.0";
    repository = "abseil/abseil-cpp";
    provider = "github-releases";
    major = 20230802;
    versionScheme = "numeric";
    riskFloor = "high";
    source = {
      authority = "github.com";
      path = [
        "abseil"
        "abseil-cpp"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-WdKXavnW7PABqBo1dJpuVRozW5SdNJGM+t4Hc3udk8U=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "abseil-cpp";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [
      cmake
      gnumake
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            tar xf $src
            cd abseil-cpp-${version}

            # Apple's multi-architecture -Xarch forwarding is only valid for
            # native universal builds. A single-architecture cross compiler
            # must select the flags from CMAKE_SYSTEM_PROCESSOR.
            sed -i \
              's/if(APPLE AND CMAKE_CXX_COMPILER_ID MATCHES \[\[Clang\]\])/if(APPLE AND CMAKE_CXX_COMPILER_ID MATCHES [[Clang]] AND NOT CMAKE_CROSSCOMPILING)/' \
              absl/copts/AbseilConfigureCopts.cmake
          ''
          else ''
            tar xf $src
            cd abseil-cpp-${version}
          '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_CXX_STANDARD=17 \
            -DBUILD_SHARED_LIBS=ON \
            -DABSL_ENABLE_INSTALL=ON \
            -DABSL_PROPAGATE_CXX_STD=ON \
            -DABSL_BUILD_TESTING=OFF
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build . -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install .
        '';
      }
    ];

    meta = {
      description = "Abseil common C++ libraries";
      homepage = "https://abseil.io";
      license = "Apache-2.0";
    };
  }
