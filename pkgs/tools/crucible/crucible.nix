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
  docPackages = builtins.filter (package: package != "crucible-cli") packages;
  docPackageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") docPackages);
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

    # The source root includes docs/, pkgs/tools/crucible/, and tests/crucible/
    # so harness lints can read RFC-0010 and AOS check wiring, while Cargo's
    # virtual workspace remains rooted at crates/.
    preBuild = ''
      cd crates
    '';

    postBuild = ''
      export RUSTDOCFLAGS="-D warnings -D missing_docs"
      cargo doc \
        --no-deps \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        --target-dir target/crucible-doc-libs \
        ${docPackageFlags}
      cargo doc \
        --no-deps \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        --target-dir target/crucible-doc-cli \
        -p crucible-cli \
        --bin crucible
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
      cargo_doc=warning-free
      rustdocflags=-D warnings -D missing_docs
      INFO
    '';

    meta = {
      description = "Crucible deterministic VM exploration workspace and CLI";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
      mainProgram = "crucible";
    };
  }
