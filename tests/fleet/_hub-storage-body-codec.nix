# Keep the observer and its optional envelope authenticator in the final tuple.
# The standalone lock is a checked subset of the selected workspace vendor.
{
  pkgs,
  source,
}: let
  native = pkgs.aos-hub;
  evidence = native.passthru.evidenceSources;
  contract = native.passthru.cargoArtifactContract;
in
  assert builtins.length evidence == 2;
  assert builtins.head evidence == native.src;
    pkgs.mkCargoPackage {
      pname = "aos-storage-body-codec";
      version = "0.1.0";
      src = source;
      cargoRoot = "tests/fleet/storage-body-codec";
      cargoDeps = builtins.elemAt evidence 1;
      cargoEnv =
        contract.cargoEnv
        // {
          # The Native test-support facade requires actual debug assertions.
          CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS = "true";
        };
      cargoFlags = "--bin aos-storage-body-codec";
      cargoTestFlags = "--bin aos-storage-body-codec";
      buildDeps = [pkgs.perl pkgs.pkg-config pkgs.openssl pkgs.sqlite pkgs.protobuf];
      runtimeDeps = [pkgs.openssl pkgs.sqlite pkgs.zlib];
      doCheck = true;
      passthru = {
        commonSourceStorePath = toString source;
        nativeFilteredSourceStorePath = toString native.src;
        lockSha256 = builtins.hashFile "sha256" (source + "/tests/fleet/storage-body-codec/Cargo.lock");
      };
      meta.description = "Confined storage body and retained envelope observation fixture";
    }
