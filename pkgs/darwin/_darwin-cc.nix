##! Darwin-native Clang/LLVM compiler wrapper.
##!
##! The cross stdenv's compiler wrapper executes on Linux and must never be
##! published as a Darwin package root.  This wrapper has the same hermetic SDK
##! and runtime defaults but uses the Darwin-hosted LLVM and bash packages, so
##! it is the `pkgs.cc` tool developers install on a Darwin machine.
{
  mkDerivation,
  stdenv,
  bash,
  llvm,
}: let
  target = stdenv.hostPlatform.config;
  sdk = stdenv.sdk;
  runtimes = stdenv.darwinRuntimes;
in
  mkDerivation {
    pname = "aos-darwin-cc-wrapper";
    version = llvm.version;
    src = null;
    buildDeps = [];
    runtimeDeps = [
      bash
      llvm
      sdk
      runtimes
    ];
    dontStrip = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/nix-support"

          cat > "$out/bin/clang" <<'AOS_DARWIN_CLANG'
          #!${bash}/bin/bash
          exec ${llvm}/bin/clang \
            --target=${target} \
            -isysroot ${sdk} \
            -mmacosx-version-min=${stdenv.deploymentTarget} \
            -fuse-ld=lld \
            -isystem ${runtimes}/include/c++/v1 \
            -L${runtimes}/lib \
            "$@"
          AOS_DARWIN_CLANG
          cat > "$out/bin/clang++" <<'AOS_DARWIN_CLANGXX'
          #!${bash}/bin/bash
          exec ${llvm}/bin/clang++ \
            --target=${target} \
            -isysroot ${sdk} \
            -mmacosx-version-min=${stdenv.deploymentTarget} \
            -fuse-ld=lld \
            -stdlib=libc++ \
            -isystem ${runtimes}/include/c++/v1 \
            -L${runtimes}/lib \
            "$@"
          AOS_DARWIN_CLANGXX
          cat > "$out/bin/ld" <<'AOS_DARWIN_LD'
          #!${bash}/bin/bash
          exec ${llvm}/bin/ld64.lld \
            -arch ${stdenv.hostPlatform.darwinArch} \
            -syslibroot ${sdk} \
            -platform_version macos ${stdenv.deploymentTarget} ${stdenv.sdkVersion} \
            -L${sdk}/usr/lib \
            "$@"
          AOS_DARWIN_LD
          chmod +x "$out/bin/clang" "$out/bin/clang++" "$out/bin/ld"

          ln -s clang "$out/bin/cc"
          ln -s clang "$out/bin/gcc"
          ln -s clang++ "$out/bin/c++"
          ln -s clang++ "$out/bin/g++"
          ln -s ld "$out/bin/ld64"
          for tool in ar nm objcopy objdump ranlib size strings strip; do
            ln -s ${llvm}/bin/llvm-$tool "$out/bin/$tool"
          done
          ln -s ${llvm}/bin/llvm-lipo "$out/bin/lipo"
          ln -s ${llvm}/bin/llvm-dwarfdump "$out/bin/dwarfdump"
          ln -s ${llvm}/bin/dsymutil "$out/bin/dsymutil"

          printf '%s\n' ${llvm} > "$out/nix-support/orig-cc"
          printf '%s\n' ${sdk} > "$out/nix-support/sysroot"
          printf '%s\n' ${target} > "$out/nix-support/target-config"
          printf '%s\n' ${stdenv.deploymentTarget} > "$out/nix-support/deployment-target"
        '';
      }
    ];

    passthru = {
      inherit llvm sdk runtimes target;
      libc = sdk;
    };
    meta = {
      description = "AOS Clang/LLVM wrapper hosted on Darwin";
      homepage = "https://llvm.org/";
      license = "Apache-2.0 WITH LLVM-exception";
    };
  }
