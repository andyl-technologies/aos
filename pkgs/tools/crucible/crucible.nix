##! crucible — RFC-0010 Crucible Rust workspace and CLI
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
}: let
  version = "0.1.0";
  src = import ./_source.nix {inherit lib;};
  packages = import ./_packages.nix;
  packageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") packages);
in
  mkCargoPackage {
    pname = "crucible";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      sourceRoot = "source/crates";
      hash = "sha256-7PIlTjQ6Cnb2k2+Qn4A49maDZSffD20krhCcwJ7od8Y=";
    };

    cargoFlags = packageFlags;
    cargoTestFlags = packageFlags;
    doCheck = true;

    # The source root includes docs/ so harness lints can read RFC-0010, while
    # Cargo's virtual workspace remains rooted at crates/.
    preBuild = ''
      cd crates
    '';

    postInstall = ''
      test -x "$out/bin/crucible"

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-build-info" <<'INFO'
      package=crucible
      build_system=mkCargoPackage
      cargo_deps=fetchCargoDeps
      cargo_workspace=crates
      cargo_packages=${packageFlags}
      INFO
    '';

    meta = {
      description = "Crucible deterministic VM exploration workspace and CLI";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
      mainProgram = "crucible";
    };
  }
