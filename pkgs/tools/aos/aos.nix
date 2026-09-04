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
  checkpolicy,
  cmake,
  libssh2,
  policycoreutils,
  pkg-config,
  protobuf,
  semodule-utils,
  sbsigntools,
  systemd,
  mtools,
  qemu-img,
  tpm2-tools,
  util-linux,
  which,
  zlib,
  zstd,
  stdenv,
  buildPackages,
}: let
  version = "0.1.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildPerl =
    if isDarwinCross
    then buildPackages.perl
    else perl;
  buildPkgConfig =
    if isDarwinCross
    then buildPackages.pkg-config
    else pkg-config;
  buildProtobuf =
    if isDarwinCross
    then buildPackages.protobuf
    else protobuf;
  buildCmake =
    if isDarwinCross
    then buildPackages.cmake
    else cmake;
  buildGitMinimal =
    if isDarwinCross
    then buildPackages.git-minimal
    else git-minimal;
  buildOpenSsh =
    if isDarwinCross
    then buildPackages.openssh
    else openssh;
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
  # The four executables share Rust libraries and one Cargo build, but their
  # installed outputs are separate security and portability boundaries. Each
  # wrapper below refers only to the tools its command surface is allowed to
  # invoke. Nix therefore computes a distinct runtime closure for every output.
  # The caller's PATH is retained solely for explicit user-supplied commands;
  # internal subprocesses always use the corresponding hermetic PATH.
  aosRuntimeTools = [bash nix qemu-img zstd];
  aprRuntimeTools = [bash nix openssl sbsigntools mtools qemu-img zstd];
  apmPortableRuntimeTools = [bash nix openssl sbsigntools mtools qemu-img tpm2-tools zstd which];
  apmRuntimeTools =
    apmPortableRuntimeTools
    ++ lib.optionals (!isDarwinCross) [systemd util-linux];
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
  linuxToolEnvironment = ''
    export AOS_LANDLOCK_WRAPPER="${aos-landlock}/bin/aos-landlock"
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
  src = import ./_workspace-source.nix {inherit lib;};
  applicationTestPackages = [
    "aos"
    "aos-cache"
    "aos-core"
    "aos-doc"
    "aos-doc-model"
    "aos-hub"
    "aos-hub-core"
    "aos-hub-worker"
    "aos-net"
    "aos-package"
    "aos-profile"
    "aos-proto"
    "aos-proto-types"
    "aos-registry-spa"
    "aos-registry-surface"
    "aos-remote"
    "aos-sandbox-core"
    "aos-sandbox-ownership-protocol"
    "aos-sandbox-protocol"
    "aos-sandbox"
    "aos-sandbox-linux"
    "aos-sandbox-host"
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
    nativeInputs = map toString [openssl buildProtobuf buildCmake libssh2];
  };
  cargoEnv = {
    OPENSSL_DIR = "${openssl}";
    OPENSSL_LIB_DIR = "${openssl}/lib";
    OPENSSL_INCLUDE_DIR = "${openssl}/include";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";
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
    buildDeps = [buildPerl buildPkgConfig openssl buildProtobuf buildCmake libssh2];
    runtimeDeps = [openssl zlib];
  };
in
  mkCargoPackage {
    pname = "aos";
    inherit version src;

    outputs = ["out" "apm" "apr" "packageRuntime"];

    cargoFlags = "-p aos";

    inherit cargoDeps cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoNextest = true;
    passthru = {
      inherit cargoArtifacts cargoDeps cargoEnv;
    };

    # cmake + libssh2: git2's vendored libgit2 is compiled from source here
    # (CMake build) with SSH smart-transport support against system libssh2.
    #
    # git-minimal + openssh are *build-only* (the `doCheck` workspace tests use
    # the host `git`/`ssh-keygen` to build repository fixtures via the test-only
    # `gitcmd`/`testutil` helpers). They are deliberately NOT in `runtimeDeps`,
    # so scrubPhase nukes their references and they never enter the runtime
    # closure — production code uses libgit2 + ssh-key, never these binaries.
    buildDeps =
      [buildPerl buildPkgConfig openssl buildProtobuf buildCmake libssh2 buildGitMinimal buildOpenSsh]
      ++ lib.optionals isDarwinCross [buildPackages.aos];
    runtimeDeps =
      [openssl zlib]
      ++ aosRuntimeTools
      ++ aprRuntimeTools
      ++ apmRuntimeTools
      ++ lib.optionals (!isDarwinCross) linuxRuntimeDeps;

    # mkDerivation normally constructs one RPATH from every runtimeDep. That
    # is correct for a single-output package, but would make each executable
    # retain the union of all four command closures here. The Rust programs
    # dynamically link only these shared libraries; command-specific tools are
    # referenced exclusively by the corresponding installed wrapper.
    NIX_LDFLAGS = "-Wl,-rpath,${openssl}/lib -Wl,-rpath,${zlib}/lib";

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
      export PROTOC="${buildProtobuf}/bin/protoc"
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
      AOS_ENVIRONMENT
                  ;;
                apr)
                  cat << 'APR_ENVIRONMENT'
      export AOS_MCOPY="${mtools}/bin/mcopy"
      export AOS_QEMU_IMG="${qemu-img}/bin/qemu-img"
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

          reject_output_reference() {
            output=$1
            dependency=$2
            if grep -R -aFq "$dependency" "$output"; then
              echo "$output unexpectedly references $dependency" >&2
              exit 1
            fi
          }
          for dependency in \
            ${sbsigntools} ${mtools} ${tpm2-tools} ${which} \
            ${lib.optionalString (!isDarwinCross) "${systemd} ${util-linux} ${builtins.concatStringsSep " " (map toString linuxRuntimeDeps)}"}; do
            reject_output_reference "$out" "$dependency"
          done
          for dependency in \
            ${tpm2-tools} ${which} \
            ${lib.optionalString (!isDarwinCross) "${systemd} ${util-linux} ${builtins.concatStringsSep " " (map toString linuxRuntimeDeps)}"}; do
            reject_output_reference "$apr" "$dependency"
          done

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
