##! aos — AOS build tool
{
  lib,
  mkCargoPackage,
  fetchCargoVendor,
  bash,
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
  systemd,
  tpm2-tools,
  which,
  zlib,
  zstd,
}: let
  version = "0.1.0";
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
  #   systemd       systemctl, for runtime package preset/attach reconciliation
  #   zstd          pack-delta compression and store decompression
  #   which         check_command_exists() preflight in the drain/sysroot path
  #   bash          wrapper interpreter; avoids relying on /bin/sh on the host
  #   systemd       systemctl: the post-activation reconcile's failed-unit
  #                 `systemctl status` capture (display-only — the reconcile
  #                 itself drives systemd over D-Bus); without it on PATH the
  #                 capture fails ENOENT and masks the real diagnostic
  # These are declared as runtimeDeps below (not just buildDeps) so the
  # scrubPhase keeps their store-path references in the wrappers and pulls them
  # into the runtime closure; without that, nuke-refs would rewrite these paths
  # to placeholders and the wrappers would point at nonexistent stores.
  runtimeTools = [bash nix systemd zstd which];
  runtimeBinPath = lib.makeBinPath runtimeTools;
  src = builtins.path {
    path = ../../../crates;
    name = "aos-crates-src";
    # Exclude every cargo target dir, not just the literal `target`: dev
    # workflows create `target-variant`, `target-debugsym`, etc., and a
    # basename-equality filter silently NAR-hashes those multi-GB build
    # trees into the "source" — making `aos-crates-src` (and every .drv
    # downstream) differ between checkouts and costing seconds of SHA-256
    # per evaluation of any system toplevel.
    filter = path: type: let
      base = baseNameOf path;
    in
      !(type == "directory" && builtins.substring 0 6 base == "target")
      && base != ".git";
  };
in
  mkCargoPackage {
    pname = "aos";
    inherit version src;

    # RFC-0007 S5 promotion: the Candidate-C one-word value carrier
    # (`candidate_c_value`) is the shipped carrier.
    cargoFlags = "-p aos --features native-eval,candidate_c_value";

    # fetchCargoVendor (not fetchCargoDeps): the workspace depends on the
    # git-sourced `nix-compat` crate from the snix MONOREPO, which the manual
    # gitDeps mechanism can't vendor (it copies a whole fetched repo as the
    # crate root). fetchCargoVendor discovers git sources from Cargo.lock and
    # extracts monorepo crate subtrees automatically.
    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "aos-vendor-${version}";
      hash = "sha256-ib53sob9o+8ZuU6bbWlhX2bhdmhB8doLWG5chMmgnRg=";
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
      export AOS_NIX_ORACLE="${nix}/bin/nix-instantiate"
      export AOS_LANDLOCK_WRAPPER="${aos-landlock}/bin/aos-landlock"
      export AOS_SELINUX_RUNNER="${aos-selinux-run}/bin/aos-selinux-run"
      export AOS_VERITY_ROOT_GUARD="${aos-verity-root-guard}/bin/aos-verity-root-guard"
      export AOS_SYSTEMD_PCREXTEND="${systemd}/lib/systemd/systemd-pcrextend"
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
    '';

    doCheck = true;
    cargoTestFlags = "--workspace --features native-eval,candidate_c_value";
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
      # mimalloc returns freed pages to the OS at once on Linux (its default
      # deferred purge retains ~100 MiB on a wide eval — 0.70x -> 0.19x of C++
      # nix-instantiate RSS, ~5% wall cost). Bash's $OSTYPE keeps this to Linux
      # (MADV_DONTNEED); macOS purge is MADV_FREE, which does not lower RSS.
      case "$OSTYPE" in linux*) export MIMALLOC_PURGE_DELAY=0 ;; esac
      exec "@SELF@" "$@"
      WRAPPER
            sed -i \
              -e "s|@PATH@|${runtimeBinPath}|" \
              -e "s|@SELF@|$out/bin/.$name-unwrapped|" \
              $out/bin/$name
            chmod +x $out/bin/$name
          done
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
