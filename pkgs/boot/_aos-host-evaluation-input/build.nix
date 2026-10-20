##! Retains the exact pregraph host descriptor as a native initrd artifact.
{
  pkgs,
  evaluationInput,
}:
pkgs.mkDerivation {
  pname = "aos-host-evaluation-input";
  version = "1";
  module = ./.;
  moduleDeps = [pkgs.aos-storage-provisioning-provider];
  src = null;
  runtimeDeps = [];
  phases = [
    {
      name = "retain-host-evaluation-input";
      script = ''
        mkdir -p "$out"
        # Retain the canonical descriptor without scanning its inert catalog
        # locators again in this package's compiler-backed build environment.
        ln -s ${evaluationInput} "$out/evaluation.json"
      '';
    }
  ];
}
