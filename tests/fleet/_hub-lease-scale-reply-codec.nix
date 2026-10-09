##! Builds only the retained-reply observer from the selected Native source.
##! It supplies historical codec evidence, never live permission or issuer keys.
{pkgs}: let
  native = pkgs.aos-hub;
  sources = native.passthru.evidenceSources;
  source = native.src;
  example = source + "/crates/aos-hub-core/examples/lease_scale_observe.rs";
  lock = source + "/crates/Cargo.lock";
  contract = native.passthru.cargoArtifactContract;
in
  assert builtins.length sources == 2;
  assert builtins.head sources == source;
    pkgs.mkCargoPackage {
      pname = "aos-hub-lease-scale-reply-observer";
      version = "0.1.0";
      src = source;
      cargoRoot = "crates";
      cargoWorkspaceMembers = import ./_hub-retained-workspace.nix source;
      cargoDeps = builtins.elemAt sources 1;
      cargoEnv = contract.cargoEnv;
      cargoFlags = "-p aos-hub-core --example lease_scale_observe";
      cargoTestFlags = "-p aos-hub-core --example lease_scale_observe";
      buildDeps = [pkgs.perl pkgs.pkg-config pkgs.openssl pkgs.sqlite pkgs.protobuf];
      runtimeDeps = [pkgs.openssl pkgs.sqlite pkgs.zlib];
      doCheck = true;
      passthru = {
        nativeSource = source;
        nativeSourceDigest = builtins.hashString "sha256" (toString source);
        codecSourceSha256 = builtins.hashFile "sha256" example;
        lockSha256 = builtins.hashFile "sha256" lock;
      };
      meta.description = "Bounded historical issuer reply observation fixture";
    }
