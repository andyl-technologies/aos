##! Linux-hosted Rust compiler with an AOS-built cross standard library.
##!
##! A cross package build must execute its compiler on the Linux scheduler.
##! This derivation augments the matching native AOS compiler with a
##! source-built target sysroot and exposes Linux wrapper commands. Package-set
##! splicing can therefore use `rust.buildTool` without executing target tools.
{
  buildPackages,
  crossCc,
  hostPlatform,
  src,
  version,
  changeId,
  configFileName,
  nativeRust ? buildPackages.rust,
  nativeLlvm ? buildPackages.llvm,
}: let
  buildTriple = buildPackages.stdenv.buildPlatform.config;
  hostTriple = hostPlatform.config;
in
  buildPackages.mkDerivation {
    pname = "rust-cross-build-tool-${hostPlatform.system}";
    inherit version src;
    targetPlatform = hostPlatform;

    buildDeps = [
      buildPackages.gnumake
      buildPackages.cmake
      buildPackages.ninja
      buildPackages.pkg-config
      buildPackages.python3
      buildPackages.bash
      buildPackages.which
      nativeRust
      nativeLlvm
      crossCc
    ];
    runtimeDeps = [nativeRust buildPackages.bash];
    dontStrip = true;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd rustc-${version}-src
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir -p .fake-bin
          printf '%s\n' '#!${buildPackages.bash}/bin/bash' 'exit 1' > .fake-bin/git
          chmod +x .fake-bin/git
          export PATH="$PWD/.fake-bin:$PATH"

          cat > ${configFileName} <<TOML
          change-id = ${toString changeId}

          [llvm]
          download-ci-llvm = false

          [build]
          build = "${buildTriple}"
          host = ["${buildTriple}"]
          target = ["${hostTriple}"]
          local-rebuild = true
          docs = false
          extended = false
          vendor = true
          profiler = true
          cargo = "${nativeRust}/bin/cargo"
          rustc = "${nativeRust}/bin/rustc"

          [rust]
          channel = "stable"
          # Zero auto-detects all physical host CPUs, bypassing x.py's job
          # limit. Keep compiler-internal code generation within the same
          # scheduler allocation as the surrounding bootstrap.
          codegen-units = $NIX_BUILD_CORES
          omit-git-hash = true
          # Target standard libraries are copied into downstream compiler
          # sysroots, so absolute bootstrap source paths would otherwise be
          # reproduced in every Darwin Rust binary built from them.
          remap-debuginfo = true
          download-rustc = false
          lld = false
          use-lld = false

          [target.${buildTriple}]
          cc = "${buildPackages.cc}/bin/cc"
          cxx = "${buildPackages.cc}/bin/c++"
          linker = "${buildPackages.cc}/bin/cc"
          ar = "${nativeLlvm}/bin/llvm-ar"
          ranlib = "${nativeLlvm}/bin/llvm-ranlib"
          llvm-config = "${nativeLlvm}/bin/llvm-config"

          [target.${hostTriple}]
          cc = "${crossCc}/bin/cc"
          cxx = "${crossCc}/bin/c++"
          linker = "${crossCc}/bin/cc"
          ar = "${crossCc}/bin/ar"
          ranlib = "${crossCc}/bin/ranlib"
          # Stage-0 local rebuilds invoke the bootstrap compiler directly, so
          # bootstrap's RUSTC_DEBUGINFO_MAP wrapper does not remap std source
          # locations despite rust.remap-debuginfo. Preserve those locations
          # under Rust's canonical virtual source prefix instead.
          rustflags = ["--remap-path-prefix=$PWD=/rustc/${version}"]
          optimized-compiler-builtins = true
          ${buildPackages.lib.optionalString hostPlatform.isDarwin ''split-debuginfo = "unpacked"''}
          TOML
        '';
      }
      {
        name = "build";
        script = ''
          export PATH="$PWD/.fake-bin:$PATH"
          export RUST_BACKTRACE=1
          # This derivation itself uses the native stdenv, whose process-wide
          # hardening selection contains build-architecture flags such as
          # x86 CET. Let each native or cross compiler wrapper select its own
          # platform defaults instead of forwarding that selection.
          unset AOS_HARDENING_ENABLE AOS_HARDENING_DISABLE

          # local-rebuild permits the matching source-built AOS compiler to
          # produce a stage-0 standard library for another target.  Only the
          # Linux bootstrap and build scripts execute.
          python3 x.py build --stage 0 library --target ${hostTriple} -j "$NIX_BUILD_CORES"
        '';
      }
      {
        name = "install";
        script = ''
          # For a local stage-0 rebuild, bootstrap leaves freshly-built target
          # artifacts in Cargo's output directory while stage0-sysroot retains
          # only its original host libraries. Use bootstrap's artifact manifest
          # so changes to Cargo's profile and dependency layout cannot silently
          # omit metadata sidecars or self-contained target objects.
          target_stamp=""
          for profile in release dist; do
            candidate="build/${buildTriple}/stage0-std/${hostTriple}/$profile/.libstd-stamp"
            if [ -f "$candidate" ]; then
              if [ -n "$target_stamp" ]; then
                echo "Rust bootstrap produced ambiguous target artifact manifests" >&2
                exit 1
              fi
              target_stamp="$candidate"
            fi
          done
          if [ -z "$target_stamp" ]; then
            echo "Rust bootstrap did not produce a target artifact manifest" >&2
            exit 1
          fi

          target_lib="$out/lib/rustlib/${hostTriple}/lib"
          mkdir -p "$out/bin" "$out/lib/rustlib"

          for entry in ${nativeRust}/lib/*; do
            name=$(basename "$entry")
            if [ "$name" != rustlib ]; then
              ln -s "$entry" "$out/lib/$name"
            fi
          done
          for entry in ${nativeRust}/lib/rustlib/*; do
            name=$(basename "$entry")
            if [ "$name" != "${hostTriple}" ]; then
              ln -s "$entry" "$out/lib/rustlib/$name"
            fi
          done
          mkdir -p "$target_lib"
          python3 - "$target_stamp" "$target_lib" <<'PYTHON'
          import pathlib
          import shutil
          import sys

          stamp = pathlib.Path(sys.argv[1]).read_bytes()
          target = pathlib.Path(sys.argv[2])
          if not stamp or not stamp.endswith(b"\0"):
              raise SystemExit("Rust artifact manifest is empty or truncated")

          # Each NUL-terminated entry has a one-byte dependency kind: host,
          # target, or target self-contained. Host tools stay in the native sysroot.
          for entry in stamp[:-1].split(b"\0"):
              kind, encoded_path = entry[:1], entry[1:]
              if kind not in (b"h", b"t", b"s") or not encoded_path:
                  raise SystemExit("Rust artifact manifest has an unknown entry")
              if kind == b"h":
                  continue

              source = pathlib.Path(encoded_path.decode())
              if not source.is_absolute() or not source.exists():
                  raise SystemExit(f"Rust target artifact is missing: {source}")
              directory = target / "self-contained" if kind == b"s" else target
              directory.mkdir(parents=True, exist_ok=True)
              destination = directory / source.name
              if destination.exists():
                  raise SystemExit(f"Rust target artifact name collides: {destination}")
              if source.is_dir():
                  shutil.copytree(source, destination)
              else:
                  shutil.copy2(source, destination)

          if not any(target.glob("libstd-*.rlib")):
              raise SystemExit("Rust artifact manifest lacks the target standard library")
          PYTHON

          for executable in ${nativeRust}/bin/*; do
            name=$(basename "$executable")
            case "$name" in
              rustc|rustdoc)
                cat > "$out/bin/$name" <<WRAPPER
          #!${buildPackages.bash}/bin/bash
          exec "$executable" --sysroot "$out" "\$@"
          WRAPPER
                chmod +x "$out/bin/$name"
                ;;
              *)
                ln -s "$executable" "$out/bin/$name"
                ;;
            esac
          done
        '';
      }
    ];

    passthru = {
      inherit hostTriple;
      targetPlatform = hostPlatform;
    };

    meta = {
      description = "Linux-hosted Rust ${version} compiler with ${hostPlatform.system} standard library";
      homepage = "https://www.rust-lang.org";
      license = "MIT OR Apache-2.0";
      platforms = [buildPackages.stdenv.buildPlatform.system];
      target = hostPlatform.constraints;
    };
  }
