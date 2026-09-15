##! aos-zfs-provider - checked OpenZFS pool and dataset provider
{
  lib,
  stdenv,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceSource,
  aosWorkspaceVendor,
  patchelf,
  zfs,
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
    family = "aos-zfs-provider-static-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [patchelf];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-zfs-provider-static-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-zfs-provider-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-block-storage-provider --bin aos-zfs-pool-provider --bin aos-zfs-dataset-provider"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-block-storage-provider"
    ];
    preBuild = staticBuildSetup;
    buildDeps = [patchelf];
  };
in
  mkCargoPackage {
    pname = "aos-zfs-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-zfs-pool-provider";
      entryPoint = "bin/aos-zfs-pool-provider";
    };

    inherit version src cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;
    cargoFlags = "-p aos-block-storage-provider --bin aos-zfs-pool-provider --bin aos-zfs-dataset-provider";
    cargoTestFlags = "-p aos-block-storage-provider";
    doCheck = true;
    buildDeps = [patchelf];
    runtimeDeps = [zfs];

    abilities = ./_aos-zfs-provider/module.nix;
    preBuild = staticBuildSetup;

    preInstall = ''
      cp "target/$CARGO_BUILD_TARGET/release/aos-zfs-pool-provider" target/release/
      cp "target/$CARGO_BUILD_TARGET/release/aos-zfs-dataset-provider" target/release/
    '';

    postInstall = ''
      mkdir -p "$out/share/aos/providers"
      cp ${./_aos-zfs-provider/pool-provider.nix} "$out/share/aos/providers/storage-pool.nix"
      cp ${./_aos-zfs-provider/dataset-provider.nix} "$out/share/aos/providers/storage-dataset.nix"
      for provider in aos-zfs-pool-provider aos-zfs-dataset-provider; do
        test -x "$out/bin/$provider"
        if patchelf --print-interpreter "$out/bin/$provider" \
            > "$TMPDIR/$provider.interpreter" 2>/dev/null; then
          printf '%s unexpectedly has ELF interpreter: ' "$provider"
          cat "$TMPDIR/$provider.interpreter"
          exit 1
        fi
      done
    '';

    meta = {
      description = "Checked OpenZFS pool and dataset provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
    };
  }
