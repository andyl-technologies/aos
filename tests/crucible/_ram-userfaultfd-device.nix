# Full-kernel device prerequisites in the existing disposable managed VM.
{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-userfaultfd-device-probe";
  version = "0";
  src = ./ram-userfaultfd-device.c;
  buildDeps = [pkgs.coreutils pkgs.linux-headers];
  phases = [
    {
      name = "build";
      script = ''
        cc -std=c11 -Wall -Wextra -Werror -pthread "$src" -o device-probe
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        cp device-probe "$out/bin/crucible-userfaultfd-device-probe"
      '';
    }
  ];
}
