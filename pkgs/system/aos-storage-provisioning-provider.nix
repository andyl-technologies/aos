##! aos-storage-provisioning-provider - checked one-time disk provisioning
{
  lib,
  stdenv,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceSource,
  aosWorkspaceVendor,
  patchelf,
  systemd,
  util-linux,
}: let
  version = "0.1.0";
  src = aosWorkspaceSource;
  cargoDeps = aosWorkspaceVendor;
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
    family = "aos-storage-provisioning-provider-static-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [patchelf];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-storage-provisioning-provider-static-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-storage-provisioning-provider-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-block-storage-provider --bin aos-storage-provisioning-provider"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-block-storage-provider -p aos-storage-provisioning"
    ];
    preBuild = staticBuildSetup;
    buildDeps = [patchelf];
  };
in
  mkCargoPackage {
    pname = "aos-storage-provisioning-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-storage-provisioning-provider";
      entryPoint = "bin/aos-storage-provisioning-provider";
    };

    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;
    cargoFlags = "-p aos-block-storage-provider --bin aos-storage-provisioning-provider";
    cargoTestFlags = "-p aos-block-storage-provider -p aos-storage-provisioning";
    doCheck = true;
    buildDeps = [patchelf];
    runtimeDeps = [systemd util-linux];

    abilities = ./_aos-storage-provisioning-provider;
    preBuild = staticBuildSetup;

    preInstall = ''
      cp "target/$CARGO_BUILD_TARGET/release/aos-storage-provisioning-provider" target/release/
    '';

    postInstall = ''
      mkdir -p "$out/share/aos/providers"
      cp ${./_aos-storage-provisioning-provider/share/aos/providers/storage-provisioning.nix} \
        "$out/share/aos/providers/storage-provisioning.nix"
      test -x "$out/bin/aos-storage-provisioning-provider"
      if patchelf --print-interpreter "$out/bin/aos-storage-provisioning-provider" \
          > "$TMPDIR/provider.interpreter" 2>/dev/null; then
        printf '%s unexpectedly has ELF interpreter: ' aos-storage-provisioning-provider
        cat "$TMPDIR/provider.interpreter"
        exit 1
      fi
    '';

    meta = {
      description = "Checked one-time storage provisioning provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }
