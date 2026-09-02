##! Linux-hosted Rust compiler with an AOS-built Darwin standard library.
##!
##! A Darwin package build cannot execute the Darwin-hosted compiler that is
##! published for target users.  This derivation augments the matching native
##! AOS compiler with a source-built Darwin sysroot and exposes Linux wrapper
##! commands.  Package-set splicing can therefore use `rust.buildTool` while
##! the ordinary `rust` output remains a genuine Darwin toolchain.
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
    pname = "rust-darwin-build-tool-${hostPlatform.system}";
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
          codegen-units = 0
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
          split-debuginfo = "unpacked"
          TOML
        '';
      }
      {
        name = "build";
        script = ''
          export PATH="$PWD/.fake-bin:$PATH"
          export RUST_BACKTRACE=1

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
          # only its original host libraries.  Assemble the target rustlib from
          # those artifacts without trying to run any Mach-O output.
          target_artifacts="build/${buildTriple}/stage0-std/${hostTriple}/release/deps"
          target_lib="$out/lib/rustlib/${hostTriple}/lib"
          target_std=$(find "$target_artifacts" -name 'libstd-*.rlib' -type f -print -quit)
          if [ -z "$target_std" ]; then
            echo "Rust bootstrap did not produce the ${hostTriple} standard library" >&2
            exit 1
          fi

          mkdir -p "$out/bin" "$out/lib/rustlib"

          for entry in ${nativeRust}/lib/*; do
            name=$(basename "$entry")
            if [ "$name" != rustlib ]; then
              ln -s "$entry" "$out/lib/$name"
            fi
          done
          for entry in ${nativeRust}/lib/rustlib/*; do
            name=$(basename "$entry")
            ln -s "$entry" "$out/lib/rustlib/$name"
          done
          mkdir -p "$target_lib"
          for library in "$target_artifacts"/*.rlib "$target_artifacts"/*.dylib; do
            if [ -f "$library" ]; then
              cp -a "$library" "$target_lib/"
            fi
          done

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
