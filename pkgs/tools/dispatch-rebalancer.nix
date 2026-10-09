##! Dispatch Rebalancer — Isolated native assignment worker.
{
  lib,
  mkDerivation,
  cmake,
  ninja,
  snappy,
  protobuf,
  nlohmann-json,
  rebalancer,
  folly,
  fbthrift-serialization,
  boost,
  fmt,
  glog,
  gflags,
  highs,
  gcc-libs,
  xxhash,
}: let
  version = "0.1.0";
  dependencies =
    [
      protobuf
      nlohmann-json
      rebalancer
      folly
      fbthrift-serialization
      boost
      boost.dev
      fmt
      glog
      gflags
      highs
      gcc-libs
      xxhash
    ]
    ++ folly.propagatedDeps ++ fbthrift-serialization.propagatedDeps ++ protobuf.propagatedDeps;
  # Installed SDK metadata searches its public dependencies separately from
  # the compiler wrapper's include and library paths.
  cmakeDependencies = dependencies;
  cmakePrefixes = builtins.concatStringsSep ";" (map builtins.toString cmakeDependencies);
  source = builtins.path {
    path = ../..;
    name = "dispatch-rebalancer-source";
    filter = path: type: let
      root = toString ../..;
      relative = builtins.substring (builtins.stringLength root + 1) (builtins.stringLength (toString path)) (toString path);
      under = prefix: relative == prefix || builtins.substring 0 (builtins.stringLength prefix + 1) relative == "${prefix}/";
    in
      relative == "" || relative == "tools" || relative == "protocol" || under "tools/dispatch-rebalancer" || under "protocol/dispatch";
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
    pname = "dispatch-rebalancer";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A cleanly closed process-protocol connection.";
        operation = "Start the native worker and close its input stream.";
        expected = "The worker releases its environment and exits successfully.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/dispatch-rebalancer"];
            stdin = "";
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A frame prefix announcing a payload beyond the protocol limit.";
        operation = "Send the oversized frame prefix to the native worker.";
        expected = "The worker rejects the frame before allocating its payload.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/dispatch-rebalancer"];
            stdin = "xxxx";
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
      };
    };
    version = "=${version}";
    cacheCCompilers = true;
    src = source;

    buildDeps = [cmake ninja];
    runtimeDeps = dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" dispatch-source
          chmod -R u+w dispatch-source
          cd dispatch-source
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S tools/dispatch-rebalancer -B build -G Ninja $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_EXE_LINKER_FLAGS="-L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib" \
            -DCMAKE_PREFIX_PATH="${cmakePrefixes}" \
            -DCMAKE_MODULE_PATH="${fbthrift-serialization}/lib/cmake/fbthrift" \
            -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON \
            -DDISPATCH_BACKEND_BUILD_ID="$out" \
            -DBUILD_TESTING=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel "$NIX_BUILD_CORES"
        '';
      }
      {
        name = "check";
        script = ''
          ctest --test-dir build --output-on-failure
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
          mkdir -p "$out/share/dispatch"
          cp protocol/dispatch/worker.proto "$out/share/dispatch/"
          # Accompany linked Snappy binaries with their pinned BSD notice.
          mkdir -p "$out/share/licenses/snappy"
          tar -xOf ${snappy.src} snappy-${snappy.version}/COPYING \
            > "$out/share/licenses/snappy/COPYING"
          test -s "$out/share/licenses/snappy/COPYING"
        '';
      }
    ];

    meta = {
      description = "Dispatch native Rebalancer worker with a versioned process protocol";
      homepage = "https://github.com/andyl-technologies/aos";
      license = "Apache-2.0";
    };
  }
