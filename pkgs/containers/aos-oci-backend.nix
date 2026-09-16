##! Package-owned OCI container and static-contract artifact backend.
{
  mkDerivation,
}:
mkDerivation {
  platformSupport = {
    build = [{abi = ["gnu"]; os = ["linux"];}];
    host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
    target = [];
    role = "build-input";
  };
  pname = "aos-oci-backend";
  version = "1";
  src = null;
  runtimeDeps = [];
  abilities = ./_aos-oci-backend;

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/aos"
        printf '%s\n' 'package-owned OCI artifact backend' > "$out/share/aos/backend"
      '';
    }
  ];

  meta = {
    description = "Package-owned OCI container and static-contract artifact backend";
    license = "Apache-2.0";
  };
}
