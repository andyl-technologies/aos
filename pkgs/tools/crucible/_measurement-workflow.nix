# Build-time immutable corpus authoring; this output never issues runtime credit.
{
  pkgs,
  lib,
  nativeCount,
  servicePolicy,
  sqliteBootstrapProof,
  campaignPolicy,
}: let
  source = import ./_source.nix {inherit lib;};
  authoredServicePolicy = pkgs.writeTextFile {
    name = "crucible-measurement-service-policy.json";
    text = builtins.toJSON servicePolicy;
  };
  generator = pkgs.mkCargoPackage {
    pname = "crucible-private-measurement-workflow-author";
    version = "0";
    src = source;
    cargoDeps = pkgs.crucible-controller.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoEnv = {
      OPENSSL_DIR = "${pkgs.openssl}";
      OPENSSL_LIB_DIR = "${pkgs.openssl}/lib";
      OPENSSL_INCLUDE_DIR = "${pkgs.openssl}/include";
      OPENSSL_NO_VENDOR = "1";
      OPENSSL_STATIC = "0";
      LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
      PROTOC = "${pkgs.protobuf}/bin/protoc";
    };
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p crucible-daemon --bin crucible-measurement-workflow --features private-measurement-domain"
    ];
    doCheck = false;
    buildDeps = [pkgs.rust.dev pkgs.pkg-config pkgs.protobuf];
    runtimeDeps = [pkgs.openssl pkgs.sqlite];
  };
in
  assert builtins.elem nativeCount [1 2 4];
  assert pkgs.qemu-crucible.passthru.qemuBuildIdentity == pkgs.qemu-crucible-source.passthru.qemuBuildIdentity;
    pkgs.mkDerivation {
      pname = "crucible-private-resident-workflow";
      version = "0";
      src = null;
      buildDeps = [generator];
      runtimeDeps = [pkgs.crucible pkgs.qemu-crucible-source sqliteBootstrapProof campaignPolicy];
      phases = [
        {
          name = "author-fixed-compact-corpus";
          script = ''
            mkdir -p "$out/share/crucible" "$out/nix-support"
            ${generator}/bin/crucible-measurement-workflow \
              "$out/share/crucible/resident-workflow" ${toString nativeCount} \
              ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
              ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
              ${authoredServicePolicy} \
              ${sqliteBootstrapProof}/share/crucible/sqlite-bootstrap/target.json \
              ${campaignPolicy}
            ln -s ${source} "$out/source"
            ln -s ${pkgs.crucible} "$out/suite"
            ln -s ${pkgs.qemu-crucible-source} "$out/corresponding-source"
            cat > "$out/nix-support/aos-release-policy" <<'POLICY'
            policy_version=1
            artifact_role=private-test-fixture
            standalone_release=false
            POLICY
          '';
        }
      ];
      passthru = {
        inherit nativeCount generator servicePolicy sqliteBootstrapProof campaignPolicy;
        privateFixture = true;
        runtimeAdmission = false;
        sourceCohort = source;
      };
    }
