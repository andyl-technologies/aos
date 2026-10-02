##! aos — AOS build tool
{
  lib,
  mkDerivation,
  mkAosCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceIntegrationSource,
  aosWorkspaceVendor,
  bash,
  ca-certificates,
  git-minimal,
  nix,
  openssh,
  perl,
  openssl,
  aos-landlock,
  service-management,
  aos-filesystem-provider,
  aos-nix-store-provider,
  cmake,
  coreutils,
  libssh2,
  pkg-config,
  protobuf,
  dbus,
  erofs-utils,
  sbsigntools,
  systemd,
  systemd-measure,
  mtools,
  nftables,
  remove-references-to,
  sqlite,
  tpm2-tools,
  util-linux,
  which,
  zlib,
  zstd,
  stdenv,
  buildPackages,
  callPackage,
  withTests ? false,
}: let
  version = "0.1.0";
  isCross = stdenv.isCross;
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildPerl =
    if isCross
    then buildPackages.perl
    else perl;
  buildPkgConfig =
    if isCross
    then buildPackages.pkg-config
    else pkg-config;
  buildProtobuf =
    if isCross
    then buildPackages.protobuf
    else protobuf;
  buildCmake =
    if isCross
    then buildPackages.cmake
    else cmake;
  buildGitMinimal =
    if isCross
    then buildPackages.git-minimal
    else git-minimal;
  buildNix =
    if isCross
    then buildPackages.nix
    else nix;
  buildOpenSsh =
    if isCross
    then buildPackages.openssh
    else openssh;
  buildZstd =
    if isCross
    then buildPackages.zstd
    else zstd;
  buildDbus =
    if isCross
    then buildPackages.dbus
    else dbus;
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
  # The five command surfaces share Rust libraries and one Cargo build. Their
  # installed wrappers remain separate portability boundaries, while apm and
  # the private package runtime share executable bytes. Each wrapper below
  # refers only to the tools its command surface is allowed to invoke, so Nix
  # still computes a bounded runtime closure for every output.
  # The caller's PATH is retained solely for explicit user-supplied commands;
  # internal subprocesses always use the corresponding hermetic PATH.
  # Local VM execution is supplied by the opt-in aos-vm wrapper or explicit
  # CLI tool paths. Release finalization uses its authenticated assembly tools.
  aosRuntimeTools = [bash git-minimal nix zstd];
  aprRuntimeTools =
    [bash nix openssl sbsigntools mtools zstd]
    ++ lib.optionals stdenv.hostPlatform.isLinux [systemd-measure];
  apmPortableRuntimeTools = [bash nix openssl sbsigntools mtools tpm2-tools zstd which];
  apmRuntimeTools =
    apmPortableRuntimeTools
    ++ lib.optionals (!isDarwinCross) [systemd util-linux];
  referenceRemovalArguments = dependencies:
    builtins.concatStringsSep " \\\n            " (map (dependency: "-t ${dependency}") dependencies);
  runtimeBinPath = tools:
    lib.concatStringsSep ":" (
      [(lib.makeBinPath tools)]
      ++ lib.optionals (!isDarwinCross && builtins.elem systemd tools) ["${systemd}/lib/systemd"]
    );
  linuxRuntimeDeps = [
    aos-landlock
  ];
  aosForbiddenRuntimeDeps =
    [sbsigntools mtools tpm2-tools which]
    ++ lib.optionals stdenv.hostPlatform.isLinux [systemd-measure]
    ++ lib.optionals (!isDarwinCross) [systemd];
  aprForbiddenRuntimeDeps =
    [tpm2-tools which]
    ++ lib.optionals (!isDarwinCross) [systemd util-linux aos-landlock];
  linuxToolEnvironment = ''
    export AOS_LANDLOCK_WRAPPER="${aos-landlock}/bin/aos-landlock"
    export AOS_UNSHARE="${util-linux}/bin/unshare"
    export AOS_PRLIMIT="${util-linux}/bin/prlimit"
    export AOS_SYSTEMD_PCREXTEND="${systemd}/lib/systemd/systemd-pcrextend"
  '';
  # Cargo's workspace owns membership; new native handlers must enter this
  # compile gate without maintaining a second list of application crates.
  workspaceManifest = builtins.fromTOML (builtins.readFile ../../../crates/Cargo.toml);
  workspacePackageNames =
    map (
      member: (builtins.fromTOML (builtins.readFile (../../../crates + "/${member}/Cargo.toml"))).package.name
    )
    workspaceManifest.workspace.members;
  applicationTestPackages = builtins.sort builtins.lessThan (lib.unique (
    builtins.filter (name: name == "aos" || lib.hasPrefix "aos-" name) workspacePackageNames
  ));
  applicationTestFlags =
    "--features aos/release-fleet-fixture "
    + builtins.concatStringsSep " " (
      map (package: "-p ${package}") applicationTestPackages
    );
  # Build both command surfaces in one feature-unified Cargo invocation so
  # their shared dependencies are compiled only once.
  releaseBuildCommands = [
    "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos -p aos-package -p aos-image-finalizer --bins --features aos/release-fleet-fixture"
  ];
  cargoDeps = aosWorkspaceVendor;
  cargoArtifactContract = {
    family =
      if withTests
      then "aos-native-release-and-test"
      else "aos-native-release";
    checkType = "debug";
    nativeInputs = map toString [openssl sqlite buildProtobuf buildCmake libssh2];
  };
  cargoEnv = {
    OPENSSL_DIR = "${openssl}";
    OPENSSL_LIB_DIR = "${openssl}/lib";
    OPENSSL_INCLUDE_DIR = "${openssl}/include";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";
    LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
    PROTOC = "${buildProtobuf}/bin/protoc";
  };
  # Native handler tests bind the same programs as their package recipe.
  # Only test derivations retain the shipped runtime: adding that dependency
  # to the ordinary CLI build would make its own output a build prerequisite.
  testCargoEnv =
    cargoEnv
    // (import ../../boot/_aos-configuration-lower/cargo-env.nix {
      inherit erofs-utils util-linux;
      packageRuntime = (callPackage ./aos.nix {withTests = false;}).packageRuntime;
    });
  cargoArtifacts = mkCargoArtifacts {
    pname =
      if withTests
      then "aos-native-release-and-test-artifacts"
      else "aos-native-release-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../../crates;
      name = "aos-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands =
      releaseBuildCommands
      ++ lib.optionals withTests [
        "test --no-run --frozen --offline -j$NIX_BUILD_CORES ${applicationTestFlags}"
      ];
    cargoEnv =
      if withTests
      then testCargoEnv
      else cargoEnv;
    buildDeps = [buildPerl buildPkgConfig buildProtobuf buildCmake];
    runtimeDeps = [openssl sqlite libssh2 zlib];
  };

  # Compiles every application test target, including the `tests/`
  # integration crates that `cargo test --lib` skips, without running them.
  # This gives a fast compile gate that does not wait on the full suite.
  testTargets = mkAosCargoPackage {
    pname = "aos-test-targets";
    inherit version cargoDeps;
    cargoArtifacts =
      if withTests
      then cargoArtifacts
      else (callPackage ./aos.nix {withTests = true;}).passthru.cargoArtifacts;
    cargoArtifactContract = cargoArtifactContract // {family = "aos-native-release-and-test";};
    cargoEnv = testCargoEnv;
    aosWorkspaceIntegrationInputs = true;
    cargoRoot = "crates";
    cargoBuildCommands = [
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES ${applicationTestFlags}"
    ];
    buildDeps = [buildPerl buildPkgConfig buildProtobuf buildCmake];
    runtimeDeps = [openssl sqlite libssh2 zlib];
    installBins = false;
    doCheck = false;
  };
in
  mkAosCargoPackage {
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
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      role = "public-package";
    };
    pname = "aos";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The command returns success and documents Usage.";
        "files" = {};
        "input" = "The packaged aos command-line interface.";
        "operation" = "Request its offline help text.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/aos\",\"--help\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"Usage\" in (result.stdout + result.stderr), (result.returncode, result.stdout, result.stderr)\nprint(\"aos operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "aos operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The command rejects the unsupported option before performing its main operation.";
        "files" = {};
        "input" = "A aos invocation containing an unsupported command-line option.";
        "operation" = "Parse the unknown option without starting a service or contacting a remote endpoint.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/aos\",\"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"aos rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "aos rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;
    aosWorkspaceIntegrationInputs = withTests;

    outputs = ["out" "apm" "apr" "packageRuntime" "testSupport"];

    module = ./_abilities;
    moduleDeps = [service-management aos-filesystem-provider aos-nix-store-provider];

    # Enforce command-surface separation after fixup and reference scrubbing.
    # Cross-linkers can leave build-environment paths in intermediate binaries;
    # the scrub phase removes those paths before Nix applies these checks.
    outputChecks = {
      out.disallowedReferences = aosForbiddenRuntimeDeps;
      apr.disallowedReferences = aprForbiddenRuntimeDeps;
    };

    cargoBuildCommands = releaseBuildCommands;

    inherit cargoDeps cargoArtifacts cargoArtifactContract;
    cargoEnv =
      if withTests
      then testCargoEnv
      else cargoEnv;
    cargoRoot = "crates";
    cargoNextest = true;
    # The CI profile retains failed output in a machine-readable report. The
    # shared Cargo phase prints its failed cases when a sandboxed check exits.
    cargoNextestProfile = "ci";
    # Compilation still uses every allocated build core. Bound concurrent test
    # processes separately so loopback servers and SQLite workers retain enough
    # scheduler time to satisfy their production-sized deadlines on large hosts.
    cargoNextestMaxTestThreads = 16;
    passthru =
      {
        inherit cargoArtifacts cargoDeps cargoEnv testTargets;
        integrationSource = aosWorkspaceIntegrationSource;
      }
      // lib.optionalAttrs (!withTests) {
        tests = callPackage ./aos.nix {withTests = true;};
      };

    # cmake builds git2's vendored libgit2 from source. OpenSSL, SQLite, and
    # libssh2 are target libraries; keeping them in runtimeDeps makes cross
    # builds expose target headers and libraries without splicing in native
    # Linux shared objects.
    #
    # openssh and zstd are build-only inputs for the check phase: the workspace
    # tests use `ssh-keygen` for repository fixtures and exercise compressed
    # registry packs. Nix supplies the multicall commands exercised by the
    # executable-resolution tests. `git-minimal` is also used by tests, but remains in
    # the `aos` runtime closure because maintainer commands create, inspect,
    # commit, and publish isolated Git worktrees without host tools.
    buildDeps =
      [buildPerl buildPkgConfig buildProtobuf buildCmake buildGitMinimal buildNix buildOpenSsh buildZstd buildDbus remove-references-to ca-certificates]
      ++ lib.optionals isDarwinCross [buildPackages.aos];
    runtimeDeps =
      [coreutils openssl sqlite libssh2 zlib]
      ++ aosRuntimeTools
      ++ aprRuntimeTools
      ++ apmRuntimeTools
      ++ lib.optionals (!isDarwinCross) linuxRuntimeDeps;

    # mkDerivation normally constructs one RPATH from every runtimeDep. That
    # is correct for a single-output package, but would make each executable
    # retain the union of all four command closures here. The Rust programs
    # dynamically link only these shared libraries; command-specific tools are
    # referenced exclusively by the corresponding installed wrapper.
    NIX_LDFLAGS = "-Wl,-rpath,${openssl}/lib -Wl,-rpath,${sqlite}/lib -Wl,-rpath,${zlib}/lib";

    # The pinned-bus cases belong to the explicit Rust test derivation. Running
    # them in the runtime build would compile a second debug dependency graph.
    postBuild = lib.optionalString withTests ''
      if [ -z "''${AOS_CROSS_COMPILING:-}" ]; then
        pinned_bus_dir="$NIX_BUILD_TOP/aos-pinned-dbus"
        pinned_bus_socket="$pinned_bus_dir/bus"
        pinned_bus_info="$pinned_bus_dir/daemon.info"
        pinned_bus_log="$pinned_bus_dir/daemon.log"
        mkdir -p "$pinned_bus_dir"
        cat > "$pinned_bus_dir/session.conf" <<EOF
      <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
       "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
      <busconfig>
        <type>session</type>
        <listen>unix:path=$pinned_bus_socket</listen>
        <auth>EXTERNAL</auth>
        <policy context="default">
          <allow send_destination="*" eavesdrop="true"/>
          <allow eavesdrop="true"/>
          <allow own="*"/>
        </policy>
      </busconfig>
      EOF

        ${buildDbus}/bin/dbus-daemon \
          --nofork \
          --nopidfile \
          --config-file="$pinned_bus_dir/session.conf" \
          --print-address=1 \
          --print-pid=1 \
          > "$pinned_bus_info" \
          2> "$pinned_bus_log" &
        pinned_bus_pid=$!
        cleanup_pinned_bus() {
          if kill -0 "$pinned_bus_pid" 2>/dev/null; then
            kill "$pinned_bus_pid"
            wait "$pinned_bus_pid" || true
          fi
        }
        trap cleanup_pinned_bus EXIT HUP INT TERM

        pinned_bus_attempt=0
        while [ ! -S "$pinned_bus_socket" ] || [ "$(wc -l < "$pinned_bus_info")" -lt 2 ]; do
          if ! kill -0 "$pinned_bus_pid" 2>/dev/null; then
            cat "$pinned_bus_log" >&2
            exit 1
          fi
          pinned_bus_attempt=$((pinned_bus_attempt + 1))
          if [ "$pinned_bus_attempt" -ge 100 ]; then
            echo "timed out waiting for the hermetic D-Bus broker" >&2
            cat "$pinned_bus_log" >&2
            exit 1
          fi
          sleep 0.05
        done

        export AOS_TEST_DBUS_ADDRESS
        AOS_TEST_DBUS_ADDRESS=$(sed -n '1p' "$pinned_bus_info")
        reported_pinned_bus_pid=$(sed -n '2p' "$pinned_bus_info")
        if [ "$reported_pinned_bus_pid" != "$pinned_bus_pid" ]; then
          echo "D-Bus broker reported pid $reported_pinned_bus_pid, expected $pinned_bus_pid" >&2
          exit 1
        fi

        # Both cases acquire the same broker name; execute them serially.
        cargo test \
          --frozen \
          --offline \
          -p aos-systemd \
          --test pinned_bus \
          -- \
          --ignored \
          --test-threads=1

        cleanup_pinned_bus
        trap - EXIT HUP INT TERM

        # Nextest does not execute public documentation examples.
        cargo test --doc --frozen --offline -j$NIX_BUILD_CORES ${applicationTestFlags}
      fi
    '';

    preBuild = ''
      # Keep the integration-test executable below the bounded verifier-
      # capture limit. Cargo's test profile is separate from dev; strip any
      # linked dependency DWARF in addition to the workspace's size-optimized
      # test profile. The shipped release artifact is built independently
      # above and is unaffected.
      # SDK clients load trust roots even when tests use loopback HTTP.
      export SSL_CERT_FILE="${ca-certificates}/etc/ssl/certs/ca-certificates.crt"
      export CARGO_PROFILE_TEST_STRIP=debuginfo
      export OPENSSL_DIR="${openssl}"
      export OPENSSL_LIB_DIR="${openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export OPENSSL_STATIC=0
      export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
      export PROTOC="${buildProtobuf}/bin/protoc"
      export AOS_NIX_INSTANTIATE="${buildNix}/bin/nix-instantiate"
      ${lib.optionalString (!isCross) ''
        ability_nix_root="$NIX_BUILD_TOP/ability-retention-nix"
        ability_nix_state="$ability_nix_root/state"
        ability_nix_log="$ability_nix_root/log"
        mkdir -p \
          "$ability_nix_state/db" \
          "$ability_nix_state/gcroots" \
          "$ability_nix_state/profiles" \
          "$ability_nix_log"

        NIX_STORE_DIR=/nix/store \
        NIX_STATE_DIR="$ability_nix_state" \
        NIX_LOG_DIR="$ability_nix_log" \
        NIX_REMOTE=local \
          ${buildNix}/bin/nix-store --init
        export AOS_TEST_ABILITY_NIX_STORE_DIR=/nix/store
        export AOS_TEST_ABILITY_NIX_STATE_DIR="$ability_nix_state"
        export AOS_TEST_ABILITY_NIX_LOG_DIR="$ability_nix_log"
        export AOS_TEST_ABILITY_NIX_REMOTE=local
      ''}
      export AOS_MCOPY="${mtools}/bin/mcopy"
      export AOS_TPM2_CREATEEK="${tpm2-tools}/bin/tpm2_createek"
      export AOS_TPM2_CREATEAK="${tpm2-tools}/bin/tpm2_createak"
      export AOS_TPM2_READPUBLIC="${tpm2-tools}/bin/tpm2_readpublic"
      export AOS_TPM2_QUOTE="${tpm2-tools}/bin/tpm2_quote"
      export AOS_TPM2_PCRREAD="${tpm2-tools}/bin/tpm2_pcrread"
      export AOS_TPM2_CHECKQUOTE="${tpm2-tools}/bin/tpm2_checkquote"
      export AOS_TPM2_FLUSHCONTEXT="${tpm2-tools}/bin/tpm2_flushcontext"
      ${lib.optionalString (!isDarwinCross) linuxToolEnvironment}
      # The real-Git interoperability test intentionally exercises stock
      # OpenSSH signing. Nix builders have numeric uids without /etc/passwd
      # entries, while ssh-keygen requires getpwuid(3) even with an explicit
      # key path. Compile the repository-owned identity shim and scope it to
      # that test's child processes; it never enters the runtime closure.
      ${
        if isDarwinCross
        then ''
          echo "native AOS policy and integration gates were validated by ${buildPackages.aos}"
        ''
        else ''
          export AOS_TEST_IDENTITY_PRELOAD="$NIX_BUILD_TOP/aos-test-identity.so"
          cc -shared -fPIC -O2 -Wall -Wextra -Werror \
            -o "$AOS_TEST_IDENTITY_PRELOAD" \
            aos-hub/tests/nix_builder_identity.c
        ''
      }
    '';

    # Package consumers need the release executables, not a second Cargo build
    # of the full workspace. The explicit Rust check enables this test phase.
    doCheck = withTests;
    # This package owns the AOS application and package-manager test surface.
    # Keep repository-aware checks out of the shipped CLI derivation so edits
    # to unrelated Nix sources do not change the runtime package identity.
    cargoTestFlags = lib.optionalString withTests applicationTestFlags;
    # Run the workspace test suite in the debug profile while the binary itself
    # ships release (installed from target/release). The registry-hub's
    # integration tests stand up loopback HTTP servers and register
    # `http://127.0.0.1` mirror/frontend/webhook URLs, which only resolve past
    # the SSRF guard when the `AOS_HUB_ALLOW_LOCAL_REMOTES` escape hatch is
    # honored — and that hatch is compiled out of release entirely by design
    # (`aos-hub-core::url_guard::allow_local_remotes` is gated on
    # `debug_assertions`, so a production binary never relaxes the guard). The
    # tests are therefore inherently debug-only; running the check phase in debug
    # exercises them exactly as the dev `cargo test` / `aos test` path does,
    # preserving full coverage without weakening the release security posture.
    checkType = "debug";

    # Install each command surface behind a thin wrapper. The public apm and
    # private package runtime share one executable in the apm output; their
    # distinct entry-point names select distinct parsers. Native effects still
    # require the signed handler artifact and current operator authority. Each
    # wrapper execs an absolute store path baked in at build time -- deriving it
    # with dirname would require coreutils on PATH and enlarge the closure.
    postInstall = ''
          write_cli_wrapper() {
            name=$1
            destination=$2
            tool_path=$3
            include_linux_environment=$4
            entry_point=$5

            mkdir -p "$destination/bin"
            {
              cat << 'WRAPPER_HEADER'
      #!${bash}/bin/bash
      export AOS_HOST_PATH="''${AOS_HOST_PATH-$PATH}"
      WRAPPER_HEADER
              if [ "$include_linux_environment" = 1 ]; then
                cat << 'LINUX_ENVIRONMENT'
      ${lib.optionalString (!isDarwinCross) linuxToolEnvironment}
      LINUX_ENVIRONMENT
              fi
              case "$name" in
                aos)
                  cat << 'AOS_ENVIRONMENT'
      export AOS_NIX_STORE="${nix}/bin/nix-store"
      ${lib.optionalString (!isDarwinCross) ''
        export AOS_LANDLOCK_WRAPPER="${aos-landlock}/bin/aos-landlock"
        export AOS_UNSHARE="${util-linux}/bin/unshare"
        export AOS_PRLIMIT="${util-linux}/bin/prlimit"
      ''}
      AOS_ENVIRONMENT
                  ;;
                apr)
                  cat << 'APR_ENVIRONMENT'
      export AOS_NIX_STORE="${nix}/bin/nix-store"
      export AOS_MCOPY="${mtools}/bin/mcopy"
      APR_ENVIRONMENT
                  ;;
                aos-boot-configuration|aos-provisioning-configuration-evaluator)
                  cat << 'PROVISIONING_ENVIRONMENT'
      export AOS_NIX_STORE="${nix}/bin/nix-store"
      export AOS_NIX_INSTANTIATE="${nix}/bin/nix-instantiate"
      PROVISIONING_ENVIRONMENT
                  ;;
                apm|aos-package-runtime)
                  cat << 'APM_ENVIRONMENT'
      ${lib.optionalString (!isDarwinCross) ''export AOS_CREDENTIAL_ENCRYPT_PROVIDER="${systemd}/bin/aos-systemd-credential-encrypt"''}
      export AOS_NIX_STORE="${nix}/bin/nix-store"
      export AOS_NIX_INSTANTIATE="${nix}/bin/nix-instantiate"
      export AOS_PACKAGE_MODULE_LIBRARY="${lib.packageModuleLibrary}"
      export AOS_MCOPY="${mtools}/bin/mcopy"
      export AOS_TPM2_CREATEEK="${tpm2-tools}/bin/tpm2_createek"
      export AOS_TPM2_CREATEAK="${tpm2-tools}/bin/tpm2_createak"
      export AOS_TPM2_READPUBLIC="${tpm2-tools}/bin/tpm2_readpublic"
      export AOS_TPM2_QUOTE="${tpm2-tools}/bin/tpm2_quote"
      export AOS_TPM2_PCRREAD="${tpm2-tools}/bin/tpm2_pcrread"
      export AOS_TPM2_CHECKQUOTE="${tpm2-tools}/bin/tpm2_checkquote"
      export AOS_TPM2_FLUSHCONTEXT="${tpm2-tools}/bin/tpm2_flushcontext"
      APM_ENVIRONMENT
                  ;;
              esac
              printf '%s\n' \
                "export PATH=\"$tool_path\"" \
                "exec \"$destination/bin/$entry_point\" \"\$@\""
            } > "$destination/bin/$name"
            chmod +x "$destination/bin/$name"
          }

          install_cli() {
            name=$1
            destination=$2
            tool_path=$3
            include_linux_environment=$4

            mkdir -p "$destination/bin"
            mv "$out/bin/$name" "$destination/bin/.$name-unwrapped"
            write_cli_wrapper \
              "$name" "$destination" "$tool_path" \
              "$include_linux_environment" ".$name-unwrapped"
          }

          install_cli aos "$out" ${lib.escapeShellArg (runtimeBinPath aosRuntimeTools)} 0
          install_cli apm "$apm" ${lib.escapeShellArg (runtimeBinPath apmRuntimeTools)} 1
          install_cli apr "$apr" ${lib.escapeShellArg (runtimeBinPath aprRuntimeTools)} 0
          # Give the shared binary the private entry-point name so
          # current_exe() resolves to the exact signed handler path. The public
          # and split-output private links preserve their own argv[0], which
          # selects the corresponding parser in crates/aos/src/apm.rs.
          mv \
            "$apm/bin/.apm-unwrapped" \
            "$apm/bin/.aos-package-runtime-unwrapped"
          ln -s .aos-package-runtime-unwrapped "$apm/bin/.apm-unwrapped"
          rm "$out/bin/aos-package-runtime"

          mkdir -p "$packageRuntime/bin"
          ln -s \
            "$apm/bin/.aos-package-runtime-unwrapped" \
            "$packageRuntime/bin/.aos-package-runtime-unwrapped"
          write_cli_wrapper \
            aos-package-runtime \
            "$packageRuntime" \
            ${lib.escapeShellArg (runtimeBinPath apmRuntimeTools)} \
            1 \
            .aos-package-runtime-unwrapped

          ${lib.optionalString (!isDarwinCross) ''
          mkdir -p "$packageRuntime/libexec"
          # Native dispatch clears its environment. Pin the evaluator's store
          # and pure-evaluation tools in its own retained executable wrapper.
          install_cli aos-boot-configuration "$packageRuntime" \
            ${lib.escapeShellArg (runtimeBinPath apmRuntimeTools)} 0
          install_cli aos-provisioning-configuration-evaluator "$packageRuntime" \
            ${lib.escapeShellArg (runtimeBinPath apmRuntimeTools)} 0
          mv \
            "$out/bin/aos-image-rollout-boot" \
            "$packageRuntime/libexec/.aos-image-rollout-boot-unwrapped"
          cat > "$packageRuntime/libexec/aos-image-rollout-boot" <<ROLLOUT_BOOT
        #!${bash}/bin/bash
        export AOS_TPM2_CHECKQUOTE="${tpm2-tools}/bin/tpm2_checkquote"
        exec "$packageRuntime/libexec/.aos-image-rollout-boot-unwrapped" "\$@"
        ROLLOUT_BOOT
          chmod +x "$packageRuntime/libexec/aos-image-rollout-boot"
          mv "$out/bin/aos-package-attestation-provider" "$packageRuntime/libexec/"
          mv "$out/bin/aos-image-rollout-observer" "$packageRuntime/libexec/"
          mv "$out/bin/aos-image-rollout-provider" "$packageRuntime/bin/"
      ''}

          grep -Fqx 'export AOS_NIX_STORE="${nix}/bin/nix-store"' "$packageRuntime/bin/aos-package-runtime"
          grep -Fqx 'export AOS_NIX_INSTANTIATE="${nix}/bin/nix-instantiate"' "$packageRuntime/bin/aos-package-runtime"
          test "$(readlink "$apm/bin/.apm-unwrapped")" = .aos-package-runtime-unwrapped
          test "$(readlink "$packageRuntime/bin/.aos-package-runtime-unwrapped")" = \
            "$apm/bin/.aos-package-runtime-unwrapped"
          ${lib.optionalString (!isDarwinCross) ''
        test -x "$packageRuntime/bin/aos-provisioning-configuration-evaluator"
        test -x "$packageRuntime/bin/aos-boot-configuration"
        test -x "$packageRuntime/libexec/aos-image-rollout-boot"
        test -x "$packageRuntime/libexec/aos-package-attestation-provider"
        test -x "$packageRuntime/libexec/aos-image-rollout-observer"
        test -x "$packageRuntime/bin/aos-image-rollout-provider"
      ''}
          ${lib.optionalString (!isDarwinCross) ''
        grep -Fqx 'export AOS_PRLIMIT="${util-linux}/bin/prlimit"' "$packageRuntime/bin/aos-package-runtime"
      ''}
          ${lib.optionalString (!isCross) ''
        if PATH=/unreachable "$apm/bin/.apm-unwrapped" apply-deployment --help > /dev/null 2>&1; then
          echo "public apm entry point accepted a private runtime command" >&2
          exit 1
        fi
        PATH=/unreachable "$apm/bin/.aos-package-runtime-unwrapped" apply-deployment --help > /dev/null
        PATH=/unreachable "$packageRuntime/bin/.aos-package-runtime-unwrapped" apply-deployment --help > /dev/null
        PATH=/unreachable "$packageRuntime/bin/aos-package-runtime" apply-deployment --help > /dev/null
      ''}

          # Release qualification fixtures belong only in the testSupport
          # output, outside every shipped CLI and package runtime closure.
          mkdir -p "$testSupport/bin"
          mv "$out/bin/aos-release-fleet-fixture" "$testSupport/bin/"
          mv "$out/bin/aos-ability-interruption-audit" "$testSupport/bin/"
          mv "$out/bin/aos-ability-authority-audit" "$testSupport/bin/"
          test -x "$testSupport/bin/aos-ability-interruption-audit"
          test -x "$testSupport/bin/aos-ability-authority-audit"

          # The common fixup phase visits only the primary output. Strip every
          # shipped executable here so the split-output closure checks inspect
          # the same bytes that are ultimately published. In particular,
          # cross-link debug records can retain tools used only by sibling
          # command surfaces.
          for binary in \
            "$out/bin/.aos-unwrapped" \
            "$apm/bin/.aos-package-runtime-unwrapped" \
            "$apr/bin/.apr-unwrapped"; do
            strip -s "$binary"
          done

          # Cargo links the binaries before they are distributed among the
          # named outputs, so its default install-prefix RPATH names $out/lib.
          # No output ships Rust shared libraries. Remove that nonexistent
          # entry so split outputs do not retain the aos output itself.
          if [ -z "''${AOS_CROSS_COMPILING:-}" ]; then
            for binary in \
              "$apm/bin/.aos-package-runtime-unwrapped" \
              "$apr/bin/.apr-unwrapped"; do
              rpath=$(patchelf --print-rpath "$binary")
              rpath=$(printf '%s' "$rpath" | sed \
                -e "s|$out/lib:||g" \
                -e "s|:$out/lib||g" \
                -e "s|^$out/lib$||")
              patchelf --set-rpath "$rpath" "$binary"
              if grep -aFq "$out" "$binary"; then
                echo "$binary retains the aos output" >&2
                exit 1
              fi
            done

            find "$packageRuntime" -type f -perm -0100 | while IFS= read -r binary; do
              if rpath=$(patchelf --print-rpath "$binary" 2>/dev/null); then
                rpath=$(printf '%s' "$rpath" | sed \
                  -e "s|$out/lib:||g" \
                  -e "s|:$out/lib||g" \
                  -e "s|^$out/lib$||")
                patchelf --set-rpath "$rpath" "$binary"
              fi
            done

            if grep -aFrq "$out" "$packageRuntime"; then
              echo "$packageRuntime retains the aos output" >&2
              exit 1
            fi
          fi

          # Cargo links all five command surfaces in one build environment, so
          # cross linkers can retain target tool paths from sibling binaries
          # even after stripping. Remove each policy-forbidden reference before
          # the general derivation scrub preserves the union of every output's
          # runtime dependencies.
          remove-references-to \
            ${referenceRemovalArguments aosForbiddenRuntimeDeps} \
            "$out/bin/.aos-unwrapped"
          remove-references-to \
            ${referenceRemovalArguments aprForbiddenRuntimeDeps} \
            "$apr/bin/.apr-unwrapped"

          # Exercise the installed wrapper, not the pre-install Cargo binary.
          # The wrapper must exec .aos-unwrapped so current_exe() materializes
          # exactly the bytes that the bundled verifier will later execute.
          ${
        if isDarwinCross
        then ''
          echo "deferring installed AOS wrapper execution until Darwin qualification"
        ''
        else ''
          wrapperMaterializerRoot="$NIX_BUILD_TOP/aos-cutover-wrapper-materializer"
          bundleRecipe="$NIX_BUILD_TOP/source/docs/rfcs/0012-hub-surface-topology/hub-topology-cutover-bundle-generation-v1.fixture.json"
          mkdir -p "$wrapperMaterializerRoot/bundle/bin"
          $out/bin/aos hub topology cutover materialize-verifier \
            --bundle "$wrapperMaterializerRoot/bundle" \
            --bundle-recipe "$bundleRecipe"
          cmp $out/bin/.aos-unwrapped "$wrapperMaterializerRoot/bundle/bin/aos"
        ''
      }
    '';

    checks = {
      testing,
      self,
      pkgs,
    }: let
      # The integration suite predates the split outputs and intentionally
      # exercises interactions among all four programs. Assemble a test-only
      # facade without reintroducing aliases in any shipped output.
      cliSuite = pkgs.mkDerivation {
        pname = "aos-cli-integration-suite";
        version = "${version}";
        src = null;
        runtimeDeps = {
          aos = self;
          apm = self.apm;
          apr = self.apr;
          package-runtime = self.packageRuntime;
        };
        phases = [
          {
            name = "install";
            script = ''
              mkdir -p "$out/bin"
              ln -s ${self}/bin/aos "$out/bin/aos"
              ln -s ${self.apm}/bin/apm "$out/bin/apm"
              ln -s ${self.apr}/bin/apr "$out/bin/apr"
              ln -s ${self.packageRuntime}/bin/aos-package-runtime "$out/bin/aos-package-runtime"
            '';
          }
        ];
      };
    in
      import ./_tests.nix {
        inherit testing pkgs;
        self = cliSuite;
      };

    meta = {
      description = "aos — AOS build tool";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
