##! aos-nix-store-provider - package-owned local Nix database handler
{
  lib,
  stdenv,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceSource,
  aosWorkspaceVendor,
  coreutils,
  grep,
  nix,
  patchelf,
}: let
  version = "0.1.0";
  src = aosWorkspaceSource;
  cargoDeps = aosWorkspaceVendor;
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
    family = "aos-nix-store-provider-static-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [patchelf];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-nix-store-provider-static-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-nix-store-provider-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-nix-store-provider --bin aos-nix-store-provider"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-nix-store-provider"
    ];
    preBuild = staticBuildSetup;
    buildDeps = [patchelf];
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "aos-nix-store-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-nix-store-provider";
      entryPoint = "libexec/aos-nix-store-provider";
    };

    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;
    cargoFlags = "-p aos-nix-store-provider --bin aos-nix-store-provider";
    cargoTestFlags = "-p aos-nix-store-provider";
    doCheck = true;
    buildDeps = [patchelf];
    runtimeDeps = [coreutils grep nix];

    abilities = ./_aos-nix-store-provider;

    preBuild = staticBuildSetup;

    preInstall = ''
      cp "target/$CARGO_BUILD_TARGET/release/aos-nix-store-provider" target/release/
    '';

    postInstall = ''
      mkdir -p "$out/libexec"
      mv "$out/bin/aos-nix-store-provider" \
        "$out/libexec/aos-nix-store-provider"
      ln -s ${nix}/bin/nix-store "$out/libexec/nix-store"
      test -x "$out/libexec/aos-nix-store-provider"
      test ! -e "$out/bin/aos-nix-store-provider"
      if patchelf --print-interpreter "$out/libexec/aos-nix-store-provider" \
          > "$TMPDIR/aos-nix-store-provider.interpreter" 2>/dev/null; then
        printf 'aos-nix-store-provider unexpectedly has ELF interpreter: '
        cat "$TMPDIR/aos-nix-store-provider.interpreter"
        exit 1
      fi
    '';

    meta = {
      description = "AOS package-owned local Nix store database provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }
