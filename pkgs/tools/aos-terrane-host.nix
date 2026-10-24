##! aos-terrane-host — host administrative quota provisioning and query broker
{
  mkCargoPackage,
  protobuf,
  buildPackages,
  terrane,
  stdenv,
}: let
  buildProtobuf =
    if stdenv.isCross
    then buildPackages.protobuf
    else protobuf;
in
  mkCargoPackage {
    platformSupport = {
      build = [
        {
          os = ["linux"];
          cpu = ["x86_64" "aarch64"];
        }
      ];
      host = [
        {
          os = ["linux"];
          cpu = ["x86_64" "aarch64"];
        }
      ];
      target = [
        {
          os = ["linux"];
          cpu = ["x86_64" "aarch64"];
        }
      ];
      role = "public-package";
    };
    pname = "aos-terrane-host";
    version = terrane.version;
    src = terrane.src;
    cargoDeps = terrane.passthru.cargoDeps;
    buildDeps = [buildProtobuf];
    cargoEnv.PROTOC = "${buildProtobuf}/bin/protoc";
    cargoRoot = "crates";
    cargoFlags = "-p aos-terrane-integration --bin aos-terrane-host";
    doCheck = false;
    meta = {
      description = "Host administrative Terrane project quota broker";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }
