##! Native kernel policy declarations independent of a selected kernel build.
{mkDerivation}:
mkDerivation {
  pname = "kernel-interface";
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
  module = ./_kernel-interface;
  phases = [
    {
      name = "install";
      script = ''mkdir -p "$out"'';
    }
  ];
  meta.description = "Kernel policy contracts shared by native package modules";
}
