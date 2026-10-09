##! Rebalancer — Generic constrained assignment optimization.
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  python3,
  boost,
  fmt,
  folly,
  fbthrift-serialization,
  glog,
  gflags,
  googletest,
  highs,
  xxhash,
  gcc-libs,
}: let
  version = "1.0.4";
  revision = "8a3f38401a92458f47909972e17a756c3c317acc";
  dependencies =
    [
      boost
      boost.dev
      fmt
      folly
      fbthrift-serialization
      glog
      gflags
      highs
      xxhash
      gcc-libs
    ]
    ++ folly.propagatedDeps ++ fbthrift-serialization.propagatedDeps;
  # Installed CMake SDKs rediscover public dependencies independently of
  # compiler search paths, including Folly's compression and crypto libraries.
  cmakeDependencies = [googletest] ++ dependencies;
  cmakePrefixes = builtins.concatStringsSep ";" (map builtins.toString cmakeDependencies);
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
    pname = "rebalancer";
    qualification.packageProbe = lib.qualification.commandProbe (let
      compilerArguments =
        ["probe.cpp" "-std=c++20" "-DREBALANCER_OSS_BUILD" "-I@out@/include" "-L@out@/lib" "-Wl,-rpath,@out@/lib"]
        ++ builtins.concatLists (map (dependency: let
          path = builtins.unsafeDiscardStringContext (toString dependency);
        in ["-I${path}/include" "-L${path}/lib" "-Wl,-rpath,${path}/lib"])
        dependencies)
        ++ ["-lrebalancer" "-lfolly" "-lthriftprotocol" "-lthriftmetadata" "-lthrifttype" "-lrpcmetadata" "-o" "probe"];
      compile = {
        argv = ["@cxx@" "@compile.rsp"];
        exit_code = 0;
      };
    in {
      primary = {
        input = "Four tasks on two hosts with a hard capacity limit.";
        operation = "Execute the installed upstream allocation smoke test.";
        expected = "The solver produces the checked two-and-two assignment.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/test_solve"];
            exit_code = 0;
          }
        ];
      };
      badInput = {
        input = "An empty problem run identity.";
        operation = "Initialize a problem with an invalid identity through the public API.";
        expected = "The problem solver rejects the empty identity.";
        files = {
          "compile.rsp" = builtins.concatStringsSep "\n" compilerArguments;
          "probe.cpp" = ''
            #include <algopt/rebalancer/interface/ProblemSolverFactory.h>
            #include <stdexcept>

            int main() {
                auto solver = facebook::rebalancer::interface::ProblemSolverFactory::makeProblemSolver("probe", "identity");
                try {
                    solver->setRunId("");
                    return 2;
                } catch (const std::runtime_error &) {
                    return 7;
                }
            }
          '';
        };
        artifacts = [];
        steps = [
          compile
          {
            argv = ["@work@/bad-input/probe"];
            exit_code = 7;
            observes_rejection = true;
          }
        ];
      };
    });
    version = "=${version}";
    cacheCCompilers = true;

    src = fetchurl {
      urls = [
        "https://github.com/facebook/rebalancer/archive/${revision}.tar.gz"
        "https://codeload.github.com/facebook/rebalancer/tar.gz/${revision}"
      ];
      hash = "sha256-DMnGJOSBoC9U5OIjE5kg2PkhtAEa4coeagnAWF2xWsQ=";
    };

    buildDeps = [cmake ninja python3 googletest];
    runtimeDeps = dependencies;
    propagatedDeps = dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd rebalancer-${revision}
          patch -p1 < ${./rebalancer-codegen-check.patch}
          # The public map aliases already select Folly's OSS implementation;
          # exported utility and test files retain unused private includes.
          patch -p1 < ${./rebalancer-oss-includes.patch}
          patch -p1 < ${./rebalancer-fmt-includes.patch}
          patch -p1 < ${./rebalancer-map-order-test.patch}
        '';
      }
      {
        name = "configure";
        script = ''
          # Upstream scans source files recursively; keep generated compiler
          # probes and Thrift output outside that source tree.
          cmake -S . -B "$TMPDIR/rebalancer-build" -G Ninja $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_BUILD_RPATH="$TMPDIR/rebalancer-build;${googletest}/lib" \
            -DCMAKE_SHARED_LINKER_FLAGS="-L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib" \
            -DCMAKE_EXE_LINKER_FLAGS="-L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib" \
            -DCMAKE_PREFIX_PATH="${cmakePrefixes}" \
            -DGTest_DIR="${googletest}/lib/cmake/GTest" \
            -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON \
            -DUSE_HIGHS=ON \
            -DPACKAGING_TEST=ON \
            -DBUILD_TESTS=ON \
            -DTESTS=ON \
            -DEXAMPLES=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build "$TMPDIR/rebalancer-build" --parallel "$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          ctest --test-dir "$TMPDIR/rebalancer-build" --output-on-failure --parallel "$NIX_BUILD_CORES"
          "$TMPDIR/rebalancer-build/test_solve"
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install "$TMPDIR/rebalancer-build"
          mkdir -p "$out/share/licenses/rebalancer"
          cp LICENSE "$out/share/licenses/rebalancer/"
          printf '%s\n' '${revision}' > "$out/share/rebalancer-source-revision"
        '';
      }
    ];

    meta = {
      description = "Generic high-performance constrained assignment library";
      homepage = "https://github.com/facebook/rebalancer";
      license = "Apache-2.0";
    };
  }
