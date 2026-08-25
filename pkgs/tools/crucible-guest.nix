##! crucible-guest — static RFC-0010 guest white-box emitter
{
  lib,
  stdenv,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoVendor,
  patchelf,
}: let
  version = "0.1.0";
  src = import ./crucible/_source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "crucible-guest-vendor-${version}";
    sourceRoot = "source/crates";
    hash = import ./crucible/_cargo-deps-hash.nix;
  };
  targetTriple =
    {
      "x86_64-linux" = "x86_64-unknown-linux-gnu";
      "aarch64-linux" = "aarch64-unknown-linux-gnu";
    }
    .${
      stdenv.hostPlatform.system
    };
  staticBuildSetup = ''
    target_triple="$(rustc -vV | sed -n 's/^host: //p')"
    test "$target_triple" = "${targetTriple}"
    rustflags_var="CARGO_TARGET_$(printf '%s' "$target_triple" | tr '[:lower:]-' '[:upper:]_')_RUSTFLAGS"
    mkdir -p "$TMPDIR/static-shim"
    ln -s "$(dirname "$(cc -print-libgcc-file-name)")/libgcc_s.a" \
      "$TMPDIR/static-shim/libgcc_eh.a"
    export "$rustflags_var=-C target-feature=+crt-static -C relocation-model=static -L $TMPDIR/static-shim"
    export CARGO_BUILD_TARGET="$target_triple"
  '';
  cargoArtifactContract = {
    family = "crucible-static-guest-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [patchelf];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "crucible-static-guest-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "crucible-static-guest-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p crucible-guest --bin crucible-guest"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p crucible-guest"
    ];
    preBuild = staticBuildSetup;
    buildDeps = [patchelf];
  };
in
  mkCargoPackage {
    pname = "crucible-guest";
    inherit version src;

    inherit cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;

    cargoFlags = "-p crucible-guest --bin crucible-guest";
    cargoTestFlags = "-p crucible-guest";
    doCheck = true;
    buildDeps = [patchelf];
    runtimeDeps = [];

    preBuild = ''
      ${staticBuildSetup}
      # crt-static linking asks for -lgcc_eh, which the AOS gcc (built with
      # shared libgcc) does not install. libgcc_s.a carries the same unwinder
      # symbols, so expose it under the name the linker wants.
      # relocation-model=static links a classic static executable instead of
      # static-pie; static-pie startup self-relocation SIGSEGVs against the
      # AOS glibc (IRELATIVE ordering), and the in-VM guest gains nothing
      # from PIE.
      # Build with an explicit --target (equal to the host triple) so cargo
      # separates host units from target units: proc-macro dylibs
      # (e.g. thiserror-impl) compile for the host WITHOUT +crt-static, which
      # cannot produce dylibs, while the guest binary itself links statically.
    '';

    preInstall = ''
      # With CARGO_BUILD_TARGET set, final artifacts live under
      # target/<triple>/release; the generic install phase scans
      # target/release, so surface the guest binary there.
      cp "target/$CARGO_BUILD_TARGET/release/crucible-guest" target/release/
    '';

    postInstall = ''
      test -x "$out/bin/crucible-guest"
      if patchelf --print-interpreter "$out/bin/crucible-guest" > "$TMPDIR/crucible-guest.interpreter" 2>/dev/null; then
        printf 'crucible-guest unexpectedly has ELF interpreter: '
        cat "$TMPDIR/crucible-guest.interpreter"
        exit 1
      fi

      doorbell_instruction_abi_version=$(sed -n \
        's/^pub const WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION: u16 = \([0-9][0-9]*\);$/\1/p' \
        crucible-protocol/src/doorbell_abi.rs)
      test -n "$doorbell_instruction_abi_version"

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-guest-build-info" <<INFO
      package=crucible-guest
      build_system=mkCargoPackage
      cargo_deps=fetchCargoVendor
      cargo_package=crucible-guest
      cargo_binary=crucible-guest
      rustflags=-C target-feature=+crt-static
      cargo_build_target=host-triple-explicit
      packaged_guest_system=${lib.system}
      doorbell_instruction_abi_version=$doorbell_instruction_abi_version
      instruction_abi_architectures=x86_64,aarch64
      abi_source=crucible-protocol::doorbell_abi::WHITEBOX_DOORBELL_ABIS
      frame_source=crucible-protocol::doorbell_frame
      marker_source=crucible-protocol::doorbell_marker
      INFO
    '';

    meta = {
      description = "Static Crucible guest marker and typed-selectable client";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "crucible-guest";
    };
  }
