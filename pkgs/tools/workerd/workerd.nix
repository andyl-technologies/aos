##! workerd — Cloudflare's Workers runtime.
##!
##! `workerd` is the open-source server runtime that powers Cloudflare Workers
##! and miniflare's local execution. miniflare spawns it to actually run a
##! Worker, so the RFC-0004 `checks.vm.worker` test needs a workerd that runs
##! under AOS glibc inside the Firecracker VM.
##!
##! ## Linux bootstrap and Darwin source builds
##!
##! Linux retains the verified binary seed used by the worker VM. Darwin cannot
##! execute or distribute that Linux ELF, so cross package sets publish the
##! matching `workerd-source` build instead. That build uses AOS Bazel and the
##! Darwin SDK to compile the full V8/Cap'n Proto/BoringSSL/ICU/Rust graph.
##!
##! ## How the seed is wrapped (no patchelf in AOS)
##!
##! The upstream npm platform package `@cloudflare/workerd-linux-64` ships a
##! ~125 MB dynamically-linked x86_64 ELF that Cloudflare built against a modern
##! glibc. AOS has no `patchelf`, so the ELF's baked-in interpreter
##! (`/lib64/ld-linux-x86-64.so.2`) cannot be rewritten in place. Instead we keep
##! the real binary at `$out/libexec/workerd` and emit `$out/bin/workerd` as an
##! AOS bash wrapper that invokes the AOS glibc dynamic loader explicitly:
##!
##! ```text
##! exec <glibc>/lib/ld-linux-x86-64.so.2 \
##!   --library-path <glibc>/lib \
##!   $out/libexec/workerd "$@"
##! ```
##!
##! The loader and library path are AOS store paths, so the runtime closure is
##! fully hermetic and the wrapper works inside the Firecracker VM (which has
##! only AOS glibc, no host `/lib64`).
##!
##! De-risk verified on the builder: the prebuilt ELF requires at most
##! GLIBC_2.29 and statically links libstdc++ (no `libstdc++.so.6` NEEDED), so it
##! runs cleanly under AOS glibc 2.39 — `workerd --version` prints
##! `workerd 2024-09-09`.
##!
##! ## Version
##!
##! Pinned to `1.20240909.0` to match `pkgs.miniflare` (miniflare 3.x). The VM
##! test injects this wrapped binary by setting `MINIFLARE_WORKERD_PATH` to
##! `${pkgs.workerd}/bin/workerd`, which miniflare honors in place of the blob in
##! its own npm closure.
{
  mkDerivation,
  fetchurl,
  glibc,
  bash,
  stdenv,
  workerd-source,
}: let
  version = "1.20240909.0";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;

  # The upstream npm platform tarball for linux-x64. Contents:
  #   package/bin/workerd   (the prebuilt ELF)
  #   package/package.json
  #   package/README.md
  src = fetchurl {
    urls = [
      "https://registry.npmjs.org/@cloudflare/workerd-linux-64/-/workerd-linux-64-${version}.tgz"
    ];
    hash = "sha256-C4lSFXS/1M1FhYDgkdoQ83TESUnRL0CM203Qmb1jvpo=";
  };
in
  if isDarwinCross
  then
    mkDerivation {
      pname = "workerd";
      inherit version;

      src = null;
      buildDeps = [];
      runtimeDeps = [];
      propagatedDeps = [];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            cp ${workerd-source}/bin/workerd "$out/bin/workerd"
            chmod +x "$out/bin/workerd"
          '';
        }
      ];

      meta = {
        description = "Cloudflare workerd Workers runtime (built from source for Darwin)";
        homepage = "https://github.com/cloudflare/workerd";
        license = "Apache-2.0";
      };
    }
  else
    mkDerivation {
      pname = "workerd";
      inherit version;

      inherit src;

      buildDeps = [];
      # The wrapper resolves the loader + libs by absolute store path, so glibc is
      # pulled into the closure via the wrapper's string references. Declaring it
      # as a runtime dep makes the dependency explicit.
      runtimeDeps = [glibc];
      propagatedDeps = [];

      phases = [
        {
          name = "unpack";
          script = ''
            tar xzf $src
            # npm tarballs root everything under package/
            cd package
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p $out/bin $out/libexec

            # Stage the prebuilt ELF. The unpack phase left us inside the npm
            # tarball's package/ root, so the binary is at bin/workerd. fetchurl
            # outputs are read-only, but the unpacked tree is writable; copy and
            # ensure the executable bit so the loader can mmap and exec it.
            cp bin/workerd $out/libexec/workerd
            chmod u+wx $out/libexec/workerd

            # Emit the AOS bash wrapper that runs the seed under the AOS glibc
            # loader. We invoke ld-linux directly (rather than relying on the ELF's
            # baked-in /lib64 interpreter) because AOS has no patchelf to rewrite
            # it, and /lib64/ld-linux does not exist in the AOS rootfs / VM.
            # --library-path supplies AOS glibc; libstdc++ is statically linked in
            # the binary, so glibc alone satisfies every NEEDED entry.
            {
              printf '%s\n' '#!${bash}/bin/bash'
              printf '%s\n' 'exec ${glibc}/lib/ld-linux-x86-64.so.2 \'
              printf '%s\n' '  --library-path ${glibc}/lib \'
              printf '%s\n' "  $out/libexec/workerd \"\$@\""
            } > $out/bin/workerd
            chmod +x $out/bin/workerd
          '';
        }
      ];

      meta = {
        description = "Cloudflare workerd Workers runtime (prebuilt binary seed wrapped for AOS glibc)";
        homepage = "https://github.com/cloudflare/workerd";
        license = "Apache-2.0";
      };

      checks = {
        testing,
        self,
        pkgs,
      }: {
        version = testing.mkVMTest {
          name = "tools-workerd-version";
          rootfsDeps = [self];
          testScript = ''
            OUTPUT=$(workerd --version 2>&1)
            case "$OUTPUT" in
              *"2024-09-09"*)
                echo "==> workerd version: PASS ($OUTPUT)"
                ;;
              *)
                echo "==> ERROR: unexpected workerd version: $OUTPUT" >&2
                exit 1
                ;;
            esac
          '';
        };
      };
    }
