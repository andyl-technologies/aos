##! accache — daemonless local compiler action cache.
{
  mkCargoPackage,
  fetchCargoDeps,
  lib,
}: let
  src = builtins.path {
    path = ../../tools/accache;
    name = "accache-source";
    # Integration fixtures are consumed by checks.build.accache separately.
    # Keep edits to that suite from rebuilding the compiler wrapper itself.
    filter = path: type:
      !(builtins.elem (baseNameOf path) ["target" "__pycache__"])
      && !(lib.hasPrefix (toString ../../tools/accache + "/tests/") path);
  };
in
  mkCargoPackage {
    pname = "accache";
    version = "0.1.0";
    inherit src;
    # The wrapper must never depend on its own configured package set.
    sharedBuildCache = false;
    cargoDeps = fetchCargoDeps {
      inherit src;
      hash = "sha256-kwgLJicESOaTdXAr1zlwHV4lTQX4LwnhjVpuRhECc9k=";
    };
    doCheck = true;
    cargoTestFlags = "--workspace";
    meta = {
      description = "Daemonless compiler action cache for Nix build contracts";
      license = "Apache-2.0";
      mainProgram = "accache";
    };
  }
