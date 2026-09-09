##! aos — AOS build tool
{
  lib,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
  bash,
  git-minimal,
  nix,
  openssh,
  perl,
  openssl,
  aos-landlock,
  aos-service-root,
  aos-selinux-run,
  aos-verity-root-guard,
  aos-ebpf-net-policy,
  aos-ebpf-lsm-policy,
  ability-package-smoke,
  checkpolicy,
  cmake,
  libssh2,
  policycoreutils,
  pkg-config,
  protobuf,
  dbus,
  semodule-utils,
  sbsigntools,
  systemd,
  mtools,
  qemu-img,
  remove-references-to,
  sqlite,
  tpm2-tools,
  util-linux,
  which,
  zlib,
  zstd,
  stdenv,
  buildPackages,
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
  # The four executables share Rust libraries and one Cargo build, but their
  # installed outputs are separate security and portability boundaries. Each
  # wrapper below refers only to the tools its command surface is allowed to
  # invoke. Nix therefore computes a distinct runtime closure for every output.
  # The caller's PATH is retained solely for explicit user-supplied commands;
  # internal subprocesses always use the corresponding hermetic PATH.
  aosRuntimeTools = [bash git-minimal nix qemu-img zstd];
  aprRuntimeTools = [bash nix openssl sbsigntools mtools qemu-img zstd];
  apmPortableRuntimeTools = [bash nix openssl sbsigntools mtools qemu-img tpm2-tools zstd which];
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
    aos-service-root
    aos-selinux-run
    aos-verity-root-guard
    aos-ebpf-net-policy
    aos-ebpf-lsm-policy
    checkpolicy
    policycoreutils
    semodule-utils
  ];
  nonAosLinuxRuntimeDeps = builtins.filter (dependency: dependency != aos-landlock) linuxRuntimeDeps;
  aosForbiddenRuntimeDeps =
    [sbsigntools mtools tpm2-tools which]
    ++ lib.optionals (!isDarwinCross) ([systemd] ++ nonAosLinuxRuntimeDeps);
  aprForbiddenRuntimeDeps =
    [tpm2-tools which]
    ++ lib.optionals (!isDarwinCross) (
      [systemd util-linux]
      ++ lib.subtractLists [checkpolicy semodule-utils] linuxRuntimeDeps
    );
  linuxToolEnvironment = ''
    export AOS_LANDLOCK_WRAPPER="${aos-landlock}/bin/aos-landlock"
    export AOS_UNSHARE="${util-linux}/bin/unshare"
    export AOS_PRLIMIT="${util-linux}/bin/prlimit"
    export AOS_SERVICE_ROOT_HELPER="${aos-service-root}/bin/aos-service-root"
    export AOS_SELINUX_RUNNER="${aos-selinux-run}/bin/aos-selinux-run"
    export AOS_VERITY_ROOT_GUARD="${aos-verity-root-guard}/bin/aos-verity-root-guard"
    export AOS_SYSTEMD_PCREXTEND="${systemd}/lib/systemd/systemd-pcrextend"
    export AOS_EBPF_NET_POLICY="${aos-ebpf-net-policy}/bin/aos-ebpf-net-policy"
    export AOS_EBPF_NET_POLICY_OBJECT="${aos-ebpf-net-policy}/lib/bpf/aos-ebpf-net-policy.bpf.o"
    export AOS_EBPF_LSM_POLICY="${aos-ebpf-lsm-policy}/bin/aos-ebpf-lsm-policy"
    export AOS_CHECKMODULE="${checkpolicy}/bin/checkmodule"
    export AOS_SEMODULE="${policycoreutils}/sbin/semodule"
    export AOS_SEMODULE_PACKAGE="${semodule-utils}/bin/semodule_package"
  '';
  abilityEvaluatorFixture = builtins.path {
    path = ../../../tests/abilities/evaluator-provider;
    name = "aos-ability-evaluator-fixture";
  };
  abilityReferenceNginxFixture = builtins.path {
    path = ../../../tests/abilities/reference-nginx/providers/nginx;
    name = "aos-ability-reference-nginx";
  };
  abilityReferenceManagedConfigurationFixture = builtins.path {
    path = ../../../tests/abilities/reference-nginx/providers/managed-configuration;
    name = "aos-ability-reference-managed-configuration";
  };
  abilityReferenceCredentialFixture = builtins.path {
    path = ../../../tests/abilities/reference-nginx/providers/credential;
    name = "aos-ability-reference-credential";
  };
  abilityReferenceSystemdFixture = builtins.path {
    path = ../../../tests/abilities/reference-nginx/providers/systemd;
    name = "aos-ability-reference-systemd";
  };
  abilityEvaluatorIfdFixture = builtins.derivation {
    name = "aos-ability-forbidden-ifd";
    system = stdenv.buildPlatform.system;
    # The evaluator receives JSON strings without Nix dependency context. Keep
    # the fixture's exact derivation identity reproducible from that same
    # context-free builder path; buildNix remains an explicit test dependency.
    builder = builtins.unsafeDiscardStringContext "${buildNix}/bin/nix-instantiate";
  };
  # Retain the .drv for the denial test without realizing its intentionally forbidden output.
  abilityEvaluatorIfdDrvPath =
    builtins.unsafeDiscardOutputDependency abilityEvaluatorIfdFixture.drvPath;
  src = import ./_workspace-source.nix {inherit lib;};
  applicationTestPackages = [
    "aos"
    "aos-ability-model"
    "aos-ability-plan"
    "aos-ability-runtime"
    "aos-ability-validate"
    "aos-cache"
    "aos-contract"
    "aos-core"
    "aos-doc"
    "aos-doc-model"
    "aos-hub"
    "aos-hub-core"
    "aos-hub-worker"
    "aos-maintain"
    "aos-net"
    "aos-oci"
    "aos-oci-types"
    "aos-package"
    "aos-profile"
    "aos-proto"
    "aos-proto-types"
    "aos-registry-spa"
    "aos-registry-surface"
    "aos-release"
    "aos-remote"
    "aos-server"
    "aos-systemd"
  ];
  applicationTestFlags = builtins.concatStringsSep " " (
    map (package: "-p ${package}") applicationTestPackages
  );
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-yf/Gu30exf9weCOK6RRrjusN+bXZ6rj1r+tZbEJMy4g=";
  };
  cargoArtifactContract = {
    family = "aos-native-release-and-test";
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
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-native-release-and-test-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../../crates;
      name = "aos-cargo-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    checkType = "debug";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos"
      "test --no-run --frozen --offline -j$NIX_BUILD_CORES ${applicationTestFlags}"
    ];
    inherit cargoEnv;
    buildDeps = [buildPerl buildPkgConfig buildProtobuf buildCmake];
    runtimeDeps = [openssl sqlite libssh2 zlib];
  };
in
  mkCargoPackage {
    pname = "aos";
    inherit version src;

    outputs = ["out" "apm" "apr" "packageRuntime" "testSupport"];

    # Enforce command-surface separation after fixup and reference scrubbing.
    # Cross-linkers can leave build-environment paths in intermediate binaries;
    # the scrub phase removes those paths before Nix applies these checks.
    outputChecks = {
      out.disallowedReferences = aosForbiddenRuntimeDeps;
      apr.disallowedReferences = aprForbiddenRuntimeDeps;
    };

    cargoFlags = "-p aos";

    inherit cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoNextest = true;
    # Compilation still uses every allocated build core. Bound concurrent test
    # processes separately so loopback servers and SQLite workers retain enough
    # scheduler time to satisfy their production-sized deadlines on large hosts.
    cargoNextestMaxTestThreads = 16;
    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
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
      [buildPerl buildPkgConfig buildProtobuf buildCmake buildGitMinimal buildNix buildOpenSsh buildZstd buildDbus remove-references-to]
      ++ lib.optionals isDarwinCross [buildPackages.aos];
    runtimeDeps =
      [openssl sqlite libssh2 zlib]
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

    postBuild = ''
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

        cargo test \
          --frozen \
          --offline \
          -p aos-systemd \
          --test pinned_bus \
          replacement_owner_cannot_complete_reused_job_path \
          -- \
          --ignored \
          --exact

        cleanup_pinned_bus
        trap - EXIT HUP INT TERM
      fi
    '';

    preBuild = ''
      # Keep the integration-test executable below the bounded verifier-
      # capture limit. Cargo's test profile is separate from dev; strip any
      # linked dependency DWARF in addition to the workspace's size-optimized
      # test profile. The shipped release artifact is built independently
      # above and is unaffected.
      export CARGO_PROFILE_TEST_STRIP=debuginfo
      export OPENSSL_DIR="${openssl}"
      export OPENSSL_LIB_DIR="${openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export OPENSSL_STATIC=0
      export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
      export PROTOC="${buildProtobuf}/bin/protoc"
      export AOS_NIX_INSTANTIATE="${buildNix}/bin/nix-instantiate"
      export AOS_TEST_ABILITY_FIXTURE="${abilityEvaluatorFixture}"
      export AOS_TEST_ABILITY_FIXTURE_NAR_HASH="sha256:$(${buildNix}/bin/nix --extra-experimental-features nix-command hash path --type sha256 --base16 ${abilityEvaluatorFixture})"
      export AOS_TEST_ABILITY_REFERENCE_NGINX="${abilityReferenceNginxFixture}"
      export AOS_TEST_ABILITY_REFERENCE_NGINX_NAR_HASH="sha256:$(${buildNix}/bin/nix --extra-experimental-features nix-command hash path --type sha256 --base16 ${abilityReferenceNginxFixture})"
      export AOS_TEST_ABILITY_REFERENCE_MANAGED_CONFIGURATION="${abilityReferenceManagedConfigurationFixture}"
      export AOS_TEST_ABILITY_REFERENCE_MANAGED_CONFIGURATION_NAR_HASH="sha256:$(${buildNix}/bin/nix --extra-experimental-features nix-command hash path --type sha256 --base16 ${abilityReferenceManagedConfigurationFixture})"
      export AOS_TEST_ABILITY_REFERENCE_CREDENTIAL="${abilityReferenceCredentialFixture}"
      export AOS_TEST_ABILITY_REFERENCE_CREDENTIAL_NAR_HASH="sha256:$(${buildNix}/bin/nix --extra-experimental-features nix-command hash path --type sha256 --base16 ${abilityReferenceCredentialFixture})"
      export AOS_TEST_ABILITY_REFERENCE_SYSTEMD="${abilityReferenceSystemdFixture}"
      export AOS_TEST_ABILITY_REFERENCE_SYSTEMD_NAR_HASH="sha256:$(${buildNix}/bin/nix --extra-experimental-features nix-command hash path --type sha256 --base16 ${abilityReferenceSystemdFixture})"
      export AOS_TEST_ABILITY_PACKAGE_SMOKE="${ability-package-smoke.abilities}"
      export AOS_TEST_ABILITY_CACHE="$NIX_BUILD_TOP/ability-evaluator-cache"
      export AOS_TEST_ABILITY_IFD_DERIVATION="${abilityEvaluatorIfdDrvPath}"
      export AOS_TEST_ABILITY_IFD_SYSTEM="${stdenv.buildPlatform.system}"
      export AOS_ABILITY_EVALUATOR_SECRET="must-not-leak"
      ${lib.optionalString isCross ''
        export AOS_TEST_ABILITY_EVALUATOR_DISABLED=1
      ''}
      export AOS_MCOPY="${mtools}/bin/mcopy"
      export AOS_QEMU_IMG="${qemu-img}/bin/qemu-img"
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

    doCheck = true;
    # This package owns the AOS application and package-manager test surface.
    # Keep repository-aware checks out of the shipped CLI derivation so edits
    # to unrelated Nix sources do not change the runtime package identity.
    cargoTestFlags = applicationTestFlags;
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

    # Install each Cargo binary into its own output behind a thin wrapper. The
    # programs have independent parsers and entry points; none derives
    # authority or command shape from argv[0]. The wrapper execs an absolute
    # store path baked in at build time -- deriving it with dirname would
    # require coreutils on PATH and enlarge the runtime contract.
    postInstall = ''
          install_cli() {
            name=$1
            destination=$2
            tool_path=$3
            include_linux_environment=$4

            mkdir -p "$destination/bin"
            mv "$out/bin/$name" "$destination/bin/.$name-unwrapped"
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
      export AOS_QEMU_IMG="${qemu-img}/bin/qemu-img"
      ${lib.optionalString (!isDarwinCross) ''
        export AOS_LANDLOCK_WRAPPER="${aos-landlock}/bin/aos-landlock"
        export AOS_UNSHARE="${util-linux}/bin/unshare"
        export AOS_PRLIMIT="${util-linux}/bin/prlimit"
      ''}
      AOS_ENVIRONMENT
                  ;;
                apr)
                  cat << 'APR_ENVIRONMENT'
      export AOS_MCOPY="${mtools}/bin/mcopy"
      export AOS_QEMU_IMG="${qemu-img}/bin/qemu-img"
      ${lib.optionalString (!isDarwinCross) ''
        export AOS_CHECKMODULE="${checkpolicy}/bin/checkmodule"
        export AOS_SEMODULE_PACKAGE="${semodule-utils}/bin/semodule_package"
      ''}
      APR_ENVIRONMENT
                  ;;
                apm|aos-package-runtime)
                  cat << 'APM_ENVIRONMENT'
      export AOS_MCOPY="${mtools}/bin/mcopy"
      export AOS_QEMU_IMG="${qemu-img}/bin/qemu-img"
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
                "exec \"$destination/bin/.$name-unwrapped\" \"\$@\""
            } > "$destination/bin/$name"
            chmod +x "$destination/bin/$name"
          }

          install_cli aos "$out" ${lib.escapeShellArg (runtimeBinPath aosRuntimeTools)} 0
          install_cli apm "$apm" ${lib.escapeShellArg (runtimeBinPath apmRuntimeTools)} 1
          install_cli apr "$apr" ${lib.escapeShellArg (runtimeBinPath aprRuntimeTools)} 0
          install_cli aos-package-runtime "$packageRuntime" ${lib.escapeShellArg (runtimeBinPath apmRuntimeTools)} 1

          # This deterministic signer/fixture process exists only for the
          # isolated fleet release exercise. Keep it out of every shipped CLI
          # output and expose it solely through the explicit testSupport output.
          mkdir -p "$testSupport/bin"
          mv "$out/bin/aos-release-fleet-fixture" "$testSupport/bin/"

          # The common fixup phase visits only the primary output. Strip every
          # shipped executable here so the split-output closure checks inspect
          # the same bytes that are ultimately published. In particular,
          # cross-link debug records can retain tools used only by sibling
          # command surfaces.
          for binary in \
            "$out/bin/.aos-unwrapped" \
            "$apm/bin/.apm-unwrapped" \
            "$apr/bin/.apr-unwrapped" \
            "$packageRuntime/bin/.aos-package-runtime-unwrapped"; do
            strip -s "$binary"
          done

          # Cargo links the binaries before they are distributed among the
          # named outputs, so its default install-prefix RPATH names $out/lib.
          # No output ships Rust shared libraries. Remove that nonexistent
          # entry so apm/apr/runtime do not retain the aos output itself.
          if [ -z "''${AOS_CROSS_COMPILING:-}" ]; then
            for binary in \
              "$apm/bin/.apm-unwrapped" \
              "$apr/bin/.apr-unwrapped" \
              "$packageRuntime/bin/.aos-package-runtime-unwrapped"; do
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
          fi

          # Cargo links all four command surfaces in one build environment, so
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
        runtimeDeps = [self self.apm self.apr self.packageRuntime];
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
