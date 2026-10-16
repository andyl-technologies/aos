##! aos-terrane-host — host administrative quota provisioning and query broker
{
  mkCargoPackage,
  terrane,
}:
mkCargoPackage {
  pname = "aos-terrane-host";
  version = terrane.version;
  src = terrane.src;
  cargoDeps = terrane.passthru.cargoDeps;
  cargoRoot = "crates";
  cargoFlags = "-p aos-terrane --bin aos-terrane-host";
  doCheck = false;
  meta = {
    description = "Host administrative Terrane project quota broker";
    platforms = ["x86_64-linux" "aarch64-linux"];
  };
}
