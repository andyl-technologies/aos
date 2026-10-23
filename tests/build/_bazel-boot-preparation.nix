##! Qualifies retained boot tools, configuration images and platform metadata.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/boot-preparation-inventory.json,
}: let
  packages = {
    aos-boot-runtime = "crates/aos/boot/aos-boot-runtime";
    aos-configuration-image = "crates/aos/boot/aos-configuration-image";
    aos-platform-metadata = "crates/aos/boot/aos-platform-metadata";
  };
  commonDependencies = {
    aos-activation = "crates/aos/activation/aos-activation";
    aos-artifact-evidence = "crates/shared/aos-artifact-evidence";
    aos-core = "crates/shared/aos-core";
    aos-module-format = "crates/aos/modules/aos-module-format";
    aos-nar = "crates/shared/aos-nar";
    aos-nix = "crates/shared/aos-nix";
    aos-storage-layout = "crates/aos/boot/aos-storage-layout";
    aos-transfer = "crates/shared/aos-transfer";
  };
  bootToolDependencies = {
    aos-boot-identity = "crates/aos/boot/aos-boot-identity";
    aos-oci-types = "crates/shared/aos-oci-types";
    aos-registry-format = "crates/aos/registry/aos-registry-format";
    aos-release-format = "crates/aos/release/aos-release-format";
  };
  commands = {
    aos-boot-runtime = ["aos-boot-preparation-provider"];
    aos-configuration-image = ["aos-certificate-bundle" "aos-configuration-boot" "aos-configuration-lower" "aos-configuration-mount"];
    aos-platform-metadata = ["aos-metadata-acquisition-provider" "aos-metadata-policy-provider"];
  };
  bootCommands = ["aos-systemd-boot-platform" "aos-systemd-image-evidence" "aos-systemd-image-stage" "aos-systemd-initrd-store"];
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  nativeLibraries = [pkgs.openssl pkgs.libssh2 pkgs.zlib pkgs.zstdStaticMultithread];
  nativeTools = [pkgs.pkg-config pkgs.cmake pkgs.perl pkgs.nix pkgs.erofs-utils pkgs.util-linux pkgs.aos.packageRuntime];
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;};
  cargoSetup = ''
    export OPENSSL_DIR="${pkgs.openssl}"
    export OPENSSL_LIB_DIR="${pkgs.openssl}/lib"
    export OPENSSL_INCLUDE_DIR="${pkgs.openssl}/include"
    export OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=0 ZSTD_SYS_USE_PKG_CONFIG=1
    export SSL_CERT_FILE="${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt"
    unset SSL_CERT_DIR
    export AOS_NIX_STORE="${pkgs.nix}/bin/nix-store"
    export AOS_NIX_INSTANTIATE="${pkgs.nix}/bin/nix-instantiate"
    export AOS_MKFS_EROFS="${pkgs.erofs-utils}/bin/mkfs.erofs"
    export AOS_FSCK_EROFS="${pkgs.erofs-utils}/bin/fsck.erofs"
    export AOS_MOUNT="${pkgs.util-linux}/bin/mount"
    export AOS_UMOUNT="${pkgs.util-linux}/bin/umount"
    export AOS_PACKAGE_RUNTIME="${pkgs.aos.packageRuntime}/bin/aos-package-runtime"
  '';
  label = name: target: "//${packages.${name}}:${target}";
  mkConfiguration = minimal: let
    profile = "boot-preparation" + pkgs.lib.optionalString minimal "-minimal";
    dependencyPackages = commonDependencies // pkgs.lib.optionalAttrs (!minimal) bootToolDependencies;
    selectedCommands =
      commands
      // {
        aos-boot-runtime = commands.aos-boot-runtime ++ pkgs.lib.optionals (!minimal) bootCommands;
      };
    commandLabels = pkgs.lib.concatMap (name: map (label name) selectedCommands.${name}) (builtins.attrNames packages);
    testLabels = pkgs.lib.concatMap (name: map (command: label name "bin_${command}") selectedCommands.${name}) (builtins.attrNames packages);
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.${profile}
      // {
        aos_native = pkgs.aosBazelNativeFoundationLibraries;
        aos_boot_tools = pkgs.aosBazelBootTools;
      };
    family = import ./_bazel-rust-family.nix {
      inherit pkgs packages dependencyPackages sourceInventory rustcFlags repositories nativeLibraries nativeTools cargoSource cargoSetup;
      pname = "aos-bazel-${profile}";
      dependencyProfile = profile;
      extraSourceDirectories = builtins.attrValues dependencyPackages;
      extraTests = testLabels;
      extraEditorTargets = commandLabels ++ map (target: target + "_binary") testLabels;
      editorComparisonScope = "selected-packages";
      editorRustcFlags = rustcFlags;
      editorDiagnosticContext = true;
      cargoFlags = pkgs.lib.optional minimal "--no-default-features";
    };
    productionTargets = commandLabels ++ pkgs.lib.concatMap (name: map (label name) ["lib" "production_license_closure"]) (builtins.attrNames packages);
    productionWorkspace = pkgs.mkAosBazelWorkspace {
      root = ../..;
      inherit sourceInventory rustcFlags repositories;
      dependencyProfile = profile;
      sourceDirectories = pkgs.lib.optionals (sourceInventory == null) (["tools/bazel" "third_party/rust"] ++ builtins.attrValues packages ++ builtins.attrValues dependencyPackages);
      analysisTargets = productionTargets;
    };
  in
    family
    // rec {
      inherit packages dependencyPackages productionWorkspace;
      inventory = pkgs.mkAosBazelBuild {
        pname = "aos-bazel-${profile}-inventory";
        workspace = family.workspace;
        inventoryOnly = true;
        targets =
          testLabels
          ++ pkgs.lib.concatMap (name: map (label name) ["unit" "doc" "license_closure" "clippy" "documentation" "format"]) (builtins.attrNames packages)
          ++ productionTargets
          ++ pkgs.lib.optionals (!minimal) [
            # Retain the dependency's nonempty integration-source discovery glob.
            "//crates/aos/release/aos-release-format:source_package"
          ];
      };
      production-inventory = pkgs.mkAosBazelBuild {
        pname = "aos-bazel-${profile}-production-inventory";
        workspace = productionWorkspace;
        inventoryOnly = true;
        targets = productionTargets;
      };
      production = pkgs.mkAosBazelBuild {
        pname = "aos-bazel-${profile}-production";
        workspace = productionWorkspace;
        targets = productionTargets;
      };
      production-cargo = pkgs.mkDerivation {
        pname = "aos-bazel-${profile}-production-cargo";
        version = "1";
        src = cargoSource;
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
              cargo build --frozen --offline --manifest-path crates/Cargo.toml --lib --bins \
                ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["-p" name]) (builtins.attrNames packages))} \
                ${pkgs.lib.optionalString minimal "--no-default-features"} \
                --jobs "$NIX_BUILD_CORES" --message-format=json > "$out/cargo-messages.jsonl"
            '';
          }
        ];
      };
      production-parity = let
        verifier = builtins.path {
          path = ../../tools/bazel/tests;
          name = "aos-boot-preparation-feature-parity-tools";
          filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
        };
        packageOptions =
          pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
          (builtins.attrNames packages)
          ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
          (builtins.attrNames dependencyPackages);
      in
        pkgs.runCommand "aos-bazel-${profile}-production-features" {buildDeps = [pkgs.python3];} ''
          mkdir -p "$out"
          ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
            --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
            --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
        '';
      all =
        pkgs.runCommand "aos-bazel-${profile}-qualified-checks" {
          buildDeps = [family.all family.editor-parity production-parity];
        } ''
          mkdir -p "$out"
          cp -r ${family.all}/evidence "$out/evidence"
          cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
          cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
          cp ${production-parity}/parity.json "$out/production-parity.json"
        '';
    };
  default = mkConfiguration false;
  without-boot-tools = mkConfiguration true;
  standaloneTargets = ["standalone" "standalone_unit" "standalone_license_closure" "standalone_clippy" "standalone_format"];
in
  default
  // rec {
    inherit default without-boot-tools;
    library-command-boundary = import ./_bazel-boot-library-boundary.nix {inherit pkgs sourceInventory;};
    standalone = pkgs.mkAosBazelCheck {
      pname = "aos-bazel-boot-preparation-standalone";
      workspace = default.workspace;
      targets = map (label "aos-boot-runtime") standaloneTargets;
    };
    standalone-inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-boot-preparation-standalone-inventory";
      workspace = default.workspace;
      inventoryOnly = true;
      targets = map (label "aos-boot-runtime") standaloneTargets;
    };
    all =
      pkgs.runCommand "aos-bazel-boot-preparation-all-configurations" {
        buildDeps = [default.all without-boot-tools.all standalone library-command-boundary];
      } ''
          mkdir -p "$out"
          cp -r ${default.all} "$out/default"
          cp -r ${without-boot-tools.all} "$out/without-boot-tools"
          cp -r ${standalone} "$out/standalone"
        cp -r ${library-command-boundary} "$out/library-command-boundary"
      '';
  }
