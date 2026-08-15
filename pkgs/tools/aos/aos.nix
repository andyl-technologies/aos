##! aos — AOS build tool
{
  lib,
  mkCargoPackage,
  fetchCargoVendor,
  bash,
  binutils,
  git-minimal,
  nix,
  openssh,
  perl,
  openssl,
  aos-landlock,
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
  qemu,
  tpm2-tools,
  util-linux,
  which,
  zlib,
  zstd,
}: let
  version = "0.1.0";
  repoRoot = ../../..;
  repoRootString = toString repoRoot;
  # Every external tool the aos/apm/apr binaries shell out to by bare name
  # (resolved via $PATH). The wrappers below set PATH to exactly this, so the
  # binaries are hermetic — their behavior never depends on the caller's
  # environment. The caller's original PATH is stashed in AOS_HOST_PATH first:
  # user-supplied commands (e.g. `apr keys register --key-command`, which
  # typically invokes a host secret manager) run with that PATH restored, while
  # every internal shell-out keeps the hermetic one. Registry, pack, object-store,
  # and SSH-signing operations no longer shell out to git/gpg/ssh-keygen — they
  # run in-process via libgit2 and the ssh-key crate (see the `registry::repo`,
  # `registry::porcelain`, and `security` modules) — so git-minimal, gnupg, and
  # openssh are gone from the runtime closure. Tools:
  #   nix           nix / nix-store: cache and store operations
  #   systemd       systemctl and systemd-measure; systemctl also captures
  #                 failed-unit diagnostics after activation reconciliation
  #   sbsigntools   sbverify for image signature verification
  #   binutils      objcopy for UKI section extraction
  #   zstd          pack-delta compression and store decompression
  #   util-linux    mount: scoped EFI System Partition remount transactions
  #   which         check_command_exists() preflight in the drain/sysroot path
  #   bash          wrapper interpreter; avoids relying on /bin/sh on the host
  # These are declared as runtimeDeps below (not just buildDeps) so the
  # scrubPhase keeps their store-path references in the wrappers and pulls them
  # into the runtime closure; without that, nuke-refs would rewrite these paths
  # to placeholders and the wrappers would point at nonexistent stores.
  runtimeTools = [bash binutils nix sbsigntools systemd mtools qemu util-linux zstd which];
  runtimeBinPath = lib.concatStringsSep ":" [
    (lib.makeBinPath runtimeTools)
    "${systemd}/lib/systemd"
  ];
  src = import ./_workspace-source.nix {inherit lib;};
  applicationTestPackages = [
    "aos"
    "aos-cache"
    "aos-core"
    "aos-doc"
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
    "aos-server"
    "aos-systemd"
  ];
  applicationTestFlags = builtins.concatStringsSep " " (
    map (package: "-p ${package}") applicationTestPackages
  );
in
  mkCargoPackage {
    pname = "aos";
    inherit version src;

    cargoFlags = "-p aos";

    # The native evaluator uses `nix-compat` from the pinned snix monorepo.
    # The lockfile-driven vendor builder extracts the crate subtree instead of
    # treating the whole monorepo as a crate root.
    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "aos-vendor-${version}";
      sourceRoot = "source/crates";
      hash = "sha256-RvgGglI1TqzOmlqgt3qG+GBHEGd3ZHT9M4CueO0Q/W4=";
    };

    # cmake + libssh2: git2's vendored libgit2 is compiled from source here
    # (CMake build) with SSH smart-transport support against system libssh2.
    #
    # git-minimal + openssh are *build-only* (the `doCheck` workspace tests use
    # the host `git`/`ssh-keygen` to build repository fixtures via the test-only
    # `gitcmd`/`testutil` helpers). They are deliberately NOT in `runtimeDeps`,
    # so scrubPhase nukes their references and they never enter the runtime
    # closure — production code uses libgit2 + ssh-key, never these binaries.
    buildDeps = [perl pkg-config openssl protobuf cmake libssh2 git-minimal openssh];
    runtimeDeps = [openssl zlib aos-landlock aos-selinux-run aos-verity-root-guard aos-ebpf-net-policy aos-ebpf-lsm-policy checkpolicy policycoreutils semodule-utils tpm2-tools] ++ runtimeTools;

    preBuild = ''
      export OPENSSL_DIR="${openssl}"
      export OPENSSL_LIB_DIR="${openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export OPENSSL_STATIC=0
      export PROTOC="${protobuf}/bin/protoc"
      export AOS_LANDLOCK_WRAPPER="${aos-landlock}/bin/aos-landlock"
      export AOS_SELINUX_RUNNER="${aos-selinux-run}/bin/aos-selinux-run"
      export AOS_VERITY_ROOT_GUARD="${aos-verity-root-guard}/bin/aos-verity-root-guard"
      export AOS_SYSTEMD_PCREXTEND="${systemd}/lib/systemd/systemd-pcrextend"
      export AOS_MCOPY="${mtools}/bin/mcopy"
      export AOS_QEMU_IMG="${qemu}/bin/qemu-img"
      export AOS_TPM2_CREATEEK="${tpm2-tools}/bin/tpm2_createek"
      export AOS_TPM2_CREATEAK="${tpm2-tools}/bin/tpm2_createak"
      export AOS_TPM2_READPUBLIC="${tpm2-tools}/bin/tpm2_readpublic"
      export AOS_TPM2_QUOTE="${tpm2-tools}/bin/tpm2_quote"
      export AOS_TPM2_PCRREAD="${tpm2-tools}/bin/tpm2_pcrread"
      export AOS_TPM2_CHECKQUOTE="${tpm2-tools}/bin/tpm2_checkquote"
      export AOS_TPM2_FLUSHCONTEXT="${tpm2-tools}/bin/tpm2_flushcontext"
      export AOS_EBPF_NET_POLICY="${aos-ebpf-net-policy}/bin/aos-ebpf-net-policy"
      export AOS_EBPF_NET_POLICY_OBJECT="${aos-ebpf-net-policy}/lib/bpf/aos-ebpf-net-policy.bpf.o"
      export AOS_EBPF_LSM_POLICY="${aos-ebpf-lsm-policy}/bin/aos-ebpf-lsm-policy"
      export AOS_CHECKMODULE="${checkpolicy}/bin/checkmodule"
      export AOS_SEMODULE="${policycoreutils}/sbin/semodule"
      export AOS_SEMODULE_PACKAGE="${semodule-utils}/bin/semodule_package"
      cd crates
      # The real-Git interoperability test intentionally exercises stock
      # OpenSSH signing. Nix builders have numeric uids without /etc/passwd
      # entries, while ssh-keygen requires getpwuid(3) even with an explicit
      # key path. Compile the repository-owned identity shim and scope it to
      # that test's child processes; it never enters the runtime closure.
      export AOS_TEST_IDENTITY_PRELOAD="$NIX_BUILD_TOP/aos-test-identity.so"
      cc -shared -fPIC -O2 -Wall -Wextra -Werror \
        -o "$AOS_TEST_IDENTITY_PRELOAD" \
        aos-hub/tests/nix_builder_identity.c
    '';

    doCheck = true;
    # This package owns the AOS application and package-manager test surface.
    # Native evaluator components are tested by `pkgs.aos-evaluator-tests`,
    # whose source intentionally includes the repository Nix/fuzz corpus. Keep
    # those repository-aware tests out of the shipped CLI derivation so edits
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

    # Each of aos/apm/apr is the same binary, dispatched by argv[0]. We install
    # a thin wrapper per name that sets the hermetic runtime PATH and execs the
    # real binary via an `.<name>-unwrapped` entry (a symlink for apm/apr) so
    # argv[0] still selects the right personality. The wrapper execs an absolute
    # store path baked in at build time — deriving it with `dirname` would
    # require coreutils on PATH, defeating the point of the minimal PATH above.
    postInstall = ''
          mv $out/bin/aos $out/bin/.aos-unwrapped
          rm -f $out/bin/apr
          ln -s .aos-unwrapped $out/bin/.apm-unwrapped
          ln -s .aos-unwrapped $out/bin/.apr-unwrapped

          for name in aos apm apr; do
            cat > $out/bin/$name << 'WRAPPER'
      #!${bash}/bin/bash
      export AOS_HOST_PATH="''${AOS_HOST_PATH-$PATH}"
      export AOS_LANDLOCK_WRAPPER="${aos-landlock}/bin/aos-landlock"
      export AOS_SELINUX_RUNNER="${aos-selinux-run}/bin/aos-selinux-run"
      export AOS_VERITY_ROOT_GUARD="${aos-verity-root-guard}/bin/aos-verity-root-guard"
      export AOS_SYSTEMD_PCREXTEND="${systemd}/lib/systemd/systemd-pcrextend"
      export AOS_MCOPY="${mtools}/bin/mcopy"
      export AOS_QEMU_IMG="${qemu}/bin/qemu-img"
      export AOS_TPM2_CREATEEK="${tpm2-tools}/bin/tpm2_createek"
      export AOS_TPM2_CREATEAK="${tpm2-tools}/bin/tpm2_createak"
      export AOS_TPM2_READPUBLIC="${tpm2-tools}/bin/tpm2_readpublic"
      export AOS_TPM2_QUOTE="${tpm2-tools}/bin/tpm2_quote"
      export AOS_TPM2_PCRREAD="${tpm2-tools}/bin/tpm2_pcrread"
      export AOS_TPM2_CHECKQUOTE="${tpm2-tools}/bin/tpm2_checkquote"
      export AOS_TPM2_FLUSHCONTEXT="${tpm2-tools}/bin/tpm2_flushcontext"
      export AOS_EBPF_NET_POLICY="${aos-ebpf-net-policy}/bin/aos-ebpf-net-policy"
      export AOS_EBPF_NET_POLICY_OBJECT="${aos-ebpf-net-policy}/lib/bpf/aos-ebpf-net-policy.bpf.o"
      export AOS_EBPF_LSM_POLICY="${aos-ebpf-lsm-policy}/bin/aos-ebpf-lsm-policy"
      export AOS_CHECKMODULE="${checkpolicy}/bin/checkmodule"
      export AOS_SEMODULE="${policycoreutils}/sbin/semodule"
      export AOS_SEMODULE_PACKAGE="${semodule-utils}/bin/semodule_package"
      export PATH="@PATH@"
      exec "@SELF@" "$@"
      WRAPPER
            sed -i \
              -e "s|@PATH@|${runtimeBinPath}|" \
              -e "s|@SELF@|$out/bin/.$name-unwrapped|" \
              $out/bin/$name
            chmod +x $out/bin/$name
          done

          # Exercise the installed wrapper, not the pre-install Cargo binary.
          # The wrapper must exec .aos-unwrapped so current_exe() materializes
          # exactly the bytes that the bundled verifier will later execute.
          wrapperMaterializerRoot="$NIX_BUILD_TOP/aos-cutover-wrapper-materializer"
          bundleRecipe="$NIX_BUILD_TOP/source/docs/rfcs/0012-hub-surface-topology/hub-topology-cutover-bundle-generation-v1.fixture.json"
          mkdir -p "$wrapperMaterializerRoot/bundle/bin"
          $out/bin/aos hub topology cutover materialize-verifier \
            --bundle "$wrapperMaterializerRoot/bundle" \
            --bundle-recipe "$bundleRecipe"
          cmp $out/bin/.aos-unwrapped "$wrapperMaterializerRoot/bundle/bin/aos"
    '';

    checks = {
      testing,
      self,
      pkgs,
    }:
      import ./_tests.nix {
        inherit testing self pkgs;
      };

    meta = {
      description = "aos — AOS build tool";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
    };
  }
