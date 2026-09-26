##! aos-network-ruleset-provider - checked nftables convergence handler
{
  lib,
  stdenv,
  mkAosCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  nftables,
  patchelf,
}: let
  version = "0.1.0";
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
    export AOS_NFT_EXECUTABLE="${nftables}/sbin/nft"
  '';
  cargoArtifactContract = {
    family = "aos-network-ruleset-provider-static-release-and-test";
    target = targetTriple;
    rustflags = "-C target-feature=+crt-static -C relocation-model=static";
    nativeInputs = map toString [patchelf];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts {
    pname = "aos-network-ruleset-provider-static-artifacts";
    inherit version cargoDeps cargoArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "aos-network-ruleset-provider-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-network-ruleset-provider --bin aos-network-ruleset-provider"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-network-ruleset-provider"
    ];
    preBuild = staticBuildSetup;
    buildDeps = [patchelf];
  };
in
  mkAosCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "aos-network-ruleset-provider";
    qualification.packageProbe = lib.qualification.providerExecutableProbe {
      name = "aos-network-ruleset-provider";
      entryPoint = "bin/aos-network-ruleset-provider";
    };

    inherit version cargoDeps cargoArtifacts cargoArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;
    cargoFlags = "-p aos-network-ruleset-provider --bin aos-network-ruleset-provider";
    cargoTestFlags = "-p aos-network-ruleset-provider";
    doCheck = true;
    buildDeps = [patchelf];
    runtimeDeps = [nftables];

    abilities = ./_aos-network-ruleset-provider;

    preBuild = staticBuildSetup;

    preInstall = ''
      cp "target/$CARGO_BUILD_TARGET/release/aos-network-ruleset-provider" target/release/
    '';

    postInstall = ''
      test -x "$out/bin/aos-network-ruleset-provider"
      if patchelf --print-interpreter "$out/bin/aos-network-ruleset-provider" \
          > "$TMPDIR/aos-network-ruleset-provider.interpreter" 2>/dev/null; then
        printf 'aos-network-ruleset-provider unexpectedly has ELF interpreter: '
        cat "$TMPDIR/aos-network-ruleset-provider.interpreter"
        exit 1
      fi
    '';

    meta = {
      description = "Checked nftables network-ruleset convergence provider";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "aos-network-ruleset-provider";
    };
  }
