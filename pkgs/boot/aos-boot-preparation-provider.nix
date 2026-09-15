##! aos-boot-preparation-provider - transaction-scoped preparation handler
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
  src = import ../tools/aos/_workspace-source.nix {inherit lib;};
  cargoDeps = fetchCargoVendor {
    inherit src;
    name = "aos-boot-preparation-provider-vendor-${version}";
    sourceRoot = "source/crates";
    hash = "sha256-2tAj5sn/KEahcZivDkx4L6CtQm958EY9m4Va91WsyR4=";
  };
  targetTriple =
    {
      "x86_64-linux" = "x86_64-unknown-linux-gnu";
      "aarch64-linux" = "aarch64-unknown-linux-gnu";
    }
    .${stdenv.hostPlatform.system};
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
    family = "aos-boot-preparation-provider-static-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [patchelf];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-boot-preparation-provider-static-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-boot-preparation-provider-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-boot-preparation-provider --bin aos-boot-preparation-provider"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-boot-preparation-provider"
    ];
    preBuild = staticBuildSetup;
    buildDeps = [patchelf];
  };
in
  mkCargoPackage {
    pname = "aos-boot-preparation-provider";
    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;
    cargoFlags = "-p aos-boot-preparation-provider --bin aos-boot-preparation-provider";
    cargoTestFlags = "-p aos-boot-preparation-provider";
    doCheck = true;
    buildDeps = [patchelf];
    runtimeDeps = [];
    abilities = ./_aos-boot-preparation-provider/module.nix;

    preBuild = staticBuildSetup;

    preInstall = ''
      cp "target/$CARGO_BUILD_TARGET/release/aos-boot-preparation-provider" target/release/
    '';

    postInstall = ''
      mkdir -p "$out/share/aos/providers"
      cp ${./_aos-boot-preparation-provider/provider.nix} \
        "$out/share/aos/providers/boot-preparation.nix"
      test -x "$out/bin/aos-boot-preparation-provider"
      if patchelf --print-interpreter "$out/bin/aos-boot-preparation-provider" \
          > "$TMPDIR/aos-boot-preparation-provider.interpreter" 2>/dev/null; then
        printf 'aos-boot-preparation-provider unexpectedly has ELF interpreter: '
        cat "$TMPDIR/aos-boot-preparation-provider.interpreter"
        exit 1
      fi
    '';

    meta = {
      description = "Transaction-scoped AOS boot preparation provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-boot-preparation-provider";
    };
  }
