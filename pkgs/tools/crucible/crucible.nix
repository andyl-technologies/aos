##! crucible — RFC-0010 Crucible Rust workspace and CLI
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  rust,
}: let
  version = "0.1.0";
  src = import ./_source.nix {inherit lib;};
  packages = import ./_packages.nix;
  packageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") packages);
  docPackages = builtins.filter (package: package != "crucible-cli") packages;
  docPackageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") docPackages);
  doctestPackages = builtins.filter (package: package != "crucible-cli" && package != "crucible-qemu-plugin") packages;
  doctestPackageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") doctestPackages);
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
    buildDeps = [rust.dev];

    # The source root includes root guidance, docs/, pkgs/tools/crucible/, and
    # tests/crucible/ so harness lints can read RFC-0010 and AOS check wiring,
    # while Cargo's virtual workspace remains rooted at crates/.
    preBuild = ''
      cd crates
    '';

    postBuild = ''
      cargo clippy \
        --all-targets \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        ${packageFlags} \
        -- \
        -D warnings
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
      cargo test \
        --doc \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        --target-dir target/crucible-doctest-libs \
        ${doctestPackageFlags}
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
      cargo_doctest=hermetic
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
