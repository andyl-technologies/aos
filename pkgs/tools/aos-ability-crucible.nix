##! aos-ability-crucible - optional RFC-0022 baseline guest adapter
{
  service-management,
  aos-filesystem-provider,
  lib,
  stdenv,
  mkAosCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  patchelf,
  sqliteStatic,
  callPackage,
  buildDriver ? "cargo",
}: let
  version = "0.1.0";
  withBuildDriver = selected: callPackage ./aos-ability-crucible.nix {buildDriver = selected;};
  cargoDeps = aosWorkspaceVendor;
  # The adapter's engine-backed release tests reach crucible-store. Keep
  # SQLite static in both the dependency artifacts and their checked consumer.
  sqliteEnvironment = {
    SQLITE3_LIB_DIR = "${sqliteStatic}/lib";
    SQLITE3_INCLUDE_DIR = "${sqliteStatic}/include";
    SQLITE3_STATIC = "1";
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
    nativeInputs = map toString [patchelf sqliteStatic];
    licenseScope = "Apache-2.0";
  };
  cargoArtifacts = mkCargoArtifacts (sqliteEnvironment
    // {
      pname = "aos-ability-crucible-static-artifacts";
      inherit version cargoDeps cargoArtifactContract;
      src = mkCargoDummySource {
        srcRoot = ../../crates;
        name = "aos-ability-crucible-dummy-source";
        cargoRoot = "crates";
      };
      cargoRoot = "crates";
      cargoBuildCommands = [
        "build --release --frozen --offline -j$NIX_BUILD_CORES -p aos-activation-crucible --bin aos-ability-crucible"
        "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p aos-activation-crucible"
      ];
      preBuild = staticBuildSetup;
      buildDeps = [patchelf sqliteStatic];
    });
  packageArguments =
    {
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
      pname = "aos-ability-crucible";
      qualification.packageProbe = lib.qualification.providerExecutableProbe {
        name = "aos-ability-crucible";
        entryPoint = "bin/aos-ability-crucible";
      };
      module = ./_aos-ability-crucible;
      moduleDeps = [service-management aos-filesystem-provider];

      inherit version cargoDeps cargoArtifacts cargoArtifactContract;
      cargoRoot = "crates";
      cargoNextest = true;
      cargoFlags = "-p aos-activation-crucible --bin aos-ability-crucible";
      cargoTestFlags = "-p aos-activation-crucible";
      doCheck = true;
      buildDeps = [patchelf sqliteStatic];
      runtimeDeps = [];
      passthru = {
        inherit withBuildDriver;
        buildDriver = "cargo";
      };

      preBuild = staticBuildSetup;

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
    // sqliteEnvironment;
  cargoPackage = mkAosCargoPackage packageArguments;
in
  assert builtins.elem buildDriver ["cargo" "bazel"];
    if buildDriver == "bazel"
    then
      callPackage ./_aos-ability-crucible-bazel.nix {
        inherit packageArguments;
        cargoFallback = cargoPackage;
      }
    else cargoPackage
