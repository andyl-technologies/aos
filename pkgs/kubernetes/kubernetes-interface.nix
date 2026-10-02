##! Native module contracts for Kubernetes controllers and add-ons.
{mkDerivation}:
mkDerivation {
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
  pname = "kubernetes-interface";
  version = "1";
  src = null;
  runtimeDeps = [];
  module = ./_kubernetes-interface;
  phases = [
    {
      name = "install";
      script = ''mkdir -p "$out/share/aos"'';
    }
  ];
  meta = {
    description = "Kubernetes and K3s native configuration contracts";
    license = "Apache-2.0";
  };
}
