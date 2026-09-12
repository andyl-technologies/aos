##! aos-ability-crucible - optional RFC-0022 baseline guest adapter
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
  src = import ./aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-ability-crucible-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-1BvvmNAo1/Y9WpBWrU4oaxUYos/uy29Bb3846j3hRpk=";
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
    family = "aos-ability-crucible-static-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [patchelf];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-ability-crucible-static-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-ability-crucible-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-ability-crucible --bin aos-ability-crucible"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-ability-crucible"
    ];
    preBuild = staticBuildSetup;
    buildDeps = [patchelf];
  };
in
  mkCargoPackage {
    pname = "aos-ability-crucible";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;
    cargoFlags = "-p aos-ability-crucible --bin aos-ability-crucible";
    cargoTestFlags = "-p aos-ability-crucible";
    doCheck = true;
    buildDeps = [patchelf];
    runtimeDeps = [];

    preBuild = staticBuildSetup;

    preInstall = ''
      cp "target/$CARGO_BUILD_TARGET/release/aos-ability-crucible" target/release/
    '';

    postInstall = ''
      test -x "$out/bin/aos-ability-crucible"
      if patchelf --print-interpreter "$out/bin/aos-ability-crucible" \
          > "$TMPDIR/aos-ability-crucible.interpreter" 2>/dev/null; then
        printf 'aos-ability-crucible unexpectedly has ELF interpreter: '
        cat "$TMPDIR/aos-ability-crucible.interpreter"
        exit 1
      fi
    '';

    meta = {
      description = "Optional AOS ability adapter for generic Crucible guest markers";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-ability-crucible";
    };
  }
