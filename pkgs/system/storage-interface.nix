##! Shared native storage readiness and policy declarations.
{mkDerivation}:
mkDerivation {
  pname = "storage-interface";
  version = "1";
  platformSupport = {
    build = [
      {
        abi = ["gnu"];
        os = ["linux"];
      }
    ];
    host = [
      {
        abi = ["gnu"];
        cpu = ["x86_64" "aarch64"];
        os = ["linux"];
      }
    ];
    target = [];
    role = "public-package";
  };
  module = ./_storage-interface;
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out"
      '';
    }
  ];
  meta.description = "Typed storage readiness and host policy contracts";
}
