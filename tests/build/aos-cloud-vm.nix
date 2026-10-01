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
        ${pkgs.python3}/bin/python3 "$src/tools/test_aos_cloud_vm.py"
        mkdir -p "$out"
        echo PASS > "$out/result"
      '';
    }
  ];
}
