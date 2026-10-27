##! accache — daemonless local compiler action cache.
{
  mkCargoPackage,
  fetchCargoDeps,
  lib,
  callPackage,
  buildDriver ? "cargo",
}: let
  src = builtins.path {
    path = ../../crates/accache;
    name = "accache-source";
    # Integration fixtures and documentation are consumed outside the Cargo
    # package. Edits there should not rebuild the compiler wrapper itself.
    filter = path: type:
      !(builtins.elem (baseNameOf path) ["target" "__pycache__" "README.md" "UPSTREAM.md"])
      && !(lib.hasPrefix (toString ../../crates/accache/accache + "/tests/") path);
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-Z6Aeg4JVtgcBX2pC3vGMYMYn6OJA8irBBpRz/isDFuQ=";
  };
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
    role = "build-input";
  };
  meta = {
    description = "Daemonless compiler action cache for Nix build contracts";
    license = "Apache-2.0";
    mainProgram = "accache";
  };
  # Package .override changes builder attributes, not callPackage arguments.
  # Re-enter the recipe explicitly so driver selection cannot silently do nothing.
  withBuildDriver = selected: callPackage ./accache.nix {buildDriver = selected;};
  cargoPackage = mkCargoPackage {
    inherit platformSupport meta;
    pname = "accache";
    version = "0.1.0";
    inherit src;
    # The wrapper must never depend on its own configured package set.
    sharedBuildCache = false;
    inherit cargoDeps;
    doCheck = true;
    cargoTestFlags = "--workspace";
    passthru = {
      inherit cargoDeps withBuildDriver;
      buildDriver = "cargo";
    };
  };
in
  assert builtins.elem buildDriver ["cargo" "bazel"];
    if buildDriver == "bazel"
    then
      callPackage ./accache/_bazel.nix {
        inherit platformSupport meta;
        passthru = {
          inherit cargoDeps withBuildDriver;
          buildDriver = "bazel";
          # Keep the independent baseline while qualification consumers migrate.
          cargoFallback = cargoPackage;
        };
      }
    else cargoPackage
