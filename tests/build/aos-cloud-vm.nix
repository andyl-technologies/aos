{pkgs}:
pkgs.mkDerivation {
  pname = "aos-cloud-vm-check";
  version = "0";
  src = ../..;
  buildDeps = [
    pkgs.bash
    pkgs.coreutils
    pkgs.gzip
    pkgs.jq
    pkgs.nix
    pkgs.python3
    pkgs.tar
  ];
  phases = [
    {
      name = "check";
      script = ''
        export NIX_REMOTE=dummy://
        ${pkgs.bash}/bin/bash -n "$src/tools/aos-cloud-vm/aos-cloud-vm.sh"
        ${pkgs.bash}/bin/bash "$src/tools/aos-cloud-vm/aos-cloud-vm.sh" --help > /dev/null
        ${pkgs.python3}/bin/python3 "$src/tools/aos-cloud-vm/test_aos_cloud_vm.py"
        mkdir -p "$out"
        echo PASS > "$out/result"
      '';
    }
  ];
}
