##! aos-cryptsetup-provider - checked encrypted block-mapping provider
{
  lib,
  stdenv,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceSource,
  aosWorkspaceVendor,
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
    family = "aos-cryptsetup-provider-static-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [patchelf];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-cryptsetup-provider-static-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-cryptsetup-provider-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-block-storage-provider --bin aos-cryptsetup-provider"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-block-storage-provider"
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
    pname = "aos-cryptsetup-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-cryptsetup-provider";
      entryPoint = "bin/aos-cryptsetup-provider";
    };

    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;
    cargoFlags = "-p aos-block-storage-provider --bin aos-cryptsetup-provider";
    cargoTestFlags = "-p aos-block-storage-provider";
    doCheck = true;
    buildDeps = [patchelf];
    runtimeDeps = [];

    abilities = ./_aos-cryptsetup-provider;

    preBuild = staticBuildSetup;

    preInstall = ''
      cp "target/$CARGO_BUILD_TARGET/release/aos-cryptsetup-provider" target/release/
    '';

    postInstall = ''
      test -x "$out/bin/aos-cryptsetup-provider"
      if patchelf --print-interpreter "$out/bin/aos-cryptsetup-provider" \
          > "$TMPDIR/aos-cryptsetup-provider.interpreter" 2>/dev/null; then
        printf 'aos-cryptsetup-provider unexpectedly has ELF interpreter: '
        cat "$TMPDIR/aos-cryptsetup-provider.interpreter"
        exit 1
      fi
    '';

    meta = {
      description = "Checked encrypted block-mapping provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-cryptsetup-provider";
    };
  }
