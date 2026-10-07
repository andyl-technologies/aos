# A separately selected read-only operator tool. This does not build or mutate
# the ordinary application tuple, install credentials, or contact a provider.
{
  pkgs,
  source,
}: let
  native = pkgs.aos-hub;
  contract = native.passthru.cargoArtifactContract;
  vendor = builtins.elemAt native.passthru.evidenceSources 1;
  inputs = [
    "crates/aos-hub/src/bin/aos-hub-provider-readback.rs"
    "crates/aos-hub/src/provider_readback/mod.rs"
    "crates/aos-hub/src/provider_readback/config.rs"
    "crates/aos-hub/src/provider_readback/journal.rs"
    "crates/aos-hub/src/provider_readback/transport.rs"
    "crates/aos-hub/src/provider_readback/tests.rs"
    "crates/aos-hub-core/src/sigv4.rs"
    "crates/aos-hub-core/src/sigv4/provider_readback.rs"
  ];
  sourceSha256 = builtins.hashString "sha256" (
    builtins.concatStringsSep "" (map (path: builtins.readFile (source + "/" + path)) inputs)
  );
in
  pkgs.mkCargoPackage {
    pname = "aos-hub-provider-readback";
    version = "0.1.0";
    src = source;
    cargoRoot = "crates";
    cargoDeps = vendor;
    cargoEnv = contract.cargoEnv // {AOS_PROVIDER_READBACK_SOURCE_SHA256 = sourceSha256;};
    cargoFlags = "--package aos-hub --bin aos-hub-provider-readback";
    cargoTestFlags = "--package aos-hub --bin aos-hub-provider-readback";
    buildDeps = [pkgs.perl pkgs.pkg-config pkgs.openssl pkgs.sqlite pkgs.protobuf];
    runtimeDeps = [pkgs.openssl pkgs.sqlite pkgs.zlib];
    doCheck = true;
    sharedBuildCache = false;
    dontNukeRefs = true;
    passthru = {
      inherit sourceSha256 inputs;
      providerQualification = false;
      evidenceSources = [source vendor];
    };
  }
