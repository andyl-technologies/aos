##! Qualifies native integration libraries with isolated production/test features.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/native-foundation-inventory.json,
}: let
  packages = {
    aos-nix = "crates/shared/aos-nix";
    aos-transfer = "crates/shared/aos-transfer";
    aos-oci = "crates/shared/aos-oci";
    aos-systemd-client = "crates/shared/aos-systemd-client";
  };
  dependencyPackages = {
    aos-core = "crates/shared/aos-core";
    aos-nar = "crates/shared/aos-nar";
    aos-oci-types = "crates/shared/aos-oci-types";
    aos-registry-format = "crates/aos/registry/aos-registry-format";
  };
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  nativeLibraries = [pkgs.openssl pkgs.libssh2 pkgs.zlib pkgs.zstdStaticMultithread];
  nativeTools = [pkgs.pkg-config pkgs.cmake pkgs.perl];
  repositories = profile:
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories.${profile}
    // {
      aos_native = pkgs.aosBazelNativeFoundationLibraries;
      aos_cli_runtime = pkgs.aosBazelCrucibleCliRuntime;
    };
  cargoSetup = ''
    export OPENSSL_DIR="${pkgs.openssl}"
    export OPENSSL_LIB_DIR="${pkgs.openssl}/lib"
    export OPENSSL_INCLUDE_DIR="${pkgs.openssl}/include"
    export OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0 ZSTD_SYS_USE_PKG_CONFIG=1
    export SSL_CERT_FILE="${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt"
    unset SSL_CERT_DIR
  '';
  mkFamily = profile: extra:
    import ./_bazel-rust-family.nix ({
        inherit pkgs packages dependencyPackages sourceInventory rustcFlags nativeLibraries nativeTools cargoSetup;
        pname = "aos-bazel-${profile}";
        dependencyProfile = profile;
        repositories = repositories profile;
        extraSourceDirectories = builtins.attrValues dependencyPackages;
        editorComparisonScope = "selected-packages";
        editorRustcFlags = rustcFlags;
        editorDiagnosticContext = true;
      }
      // extra);
  default = mkFamily "native-foundation-tests" {};
  without-transfer = mkFamily "native-foundation-minimal" {
    cargoFlags = ["--no-default-features"];
    packageTargets =
      builtins.mapAttrs (name: _: {
        root =
          if name == "aos-transfer"
          then "lib_without_transfer"
          else "lib";
        unit =
          if name == "aos-transfer"
          then "unit_without_transfer"
          else "unit";
        doctest =
          if name == "aos-transfer"
          then "doc_without_transfer"
          else "doc";
        license =
          if name == "aos-transfer"
          then "license_closure_without_transfer"
          else "license_closure";
      })
      packages;
    packageTargetSuffixes.aos-transfer = "_without_transfer";
  };
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags;
    dependencyProfile = "native-foundation";
    repositories = repositories "native-foundation";
    sourceDirectories = pkgs.lib.optionals (sourceInventory == null) (["tools/bazel" "third_party/rust"] ++ builtins.attrValues packages ++ builtins.attrValues dependencyPackages);
    analysisTargets = map (path: "//${path}:lib") (builtins.attrValues packages);
  };
in
  default
  // rec {
    inherit default without-transfer productionWorkspace;
    library-metadata = import ./_bazel-native-foundation-libraries.nix {inherit pkgs;};
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-native-foundation-production-cargo";
      version = "1";
      src = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;};
      buildDeps = [pkgs.rust pkgs.sed] ++ nativeTools;
      runtimeDeps = nativeLibraries;
      sharedBuildCache = false;
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "compile";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
            export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target"
            mkdir -p "$CARGO_HOME" .cargo "$out"
            sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
              ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
            ${cargoSetup}
            cargo build --frozen --offline --manifest-path crates/Cargo.toml --lib \
              ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["-p" name]) (builtins.attrNames packages))} \
              --jobs "$NIX_BUILD_CORES" --message-format=json > "$out/cargo-messages.jsonl"
          '';
        }
      ];
    };
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-native-foundation-production";
      workspace = productionWorkspace;
      targets = pkgs.lib.concatMap (path: ["//${path}:lib" "//${path}:production_license_closure"]) (builtins.attrValues packages);
    };
    production-parity = let
      verifier = builtins.path {
        path = ../../tools/bazel/tests;
        name = "aos-native-foundation-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"]) (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-native-foundation-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    all =
      pkgs.runCommand "aos-bazel-native-foundation-qualified-checks" {
        buildDeps = [default.all default.editor-parity without-transfer.tests without-transfer.oracle production-parity library-metadata];
      } ''
        mkdir -p "$out"
        cp -r ${default.all}/evidence "$out/evidence"
        cp ${default.all}/inventory.json ${default.all}/parity.json "$out/"
        cp ${default.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${without-transfer.oracle}/parity.json "$out/without-transfer-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
        cp ${library-metadata}/report.json "$out/native-libraries.json"
      '';
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-native-foundation-inventory";
      workspace = default.workspace;
      inventoryOnly = true;
      targets = pkgs.lib.concatMap (path:
        map (target: "//${path}:${target}") ["unit" "doc" "license_closure" "clippy" "documentation" "format"])
      (builtins.attrValues packages);
    };
  }
