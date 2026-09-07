# tests/build/sandbox-linux-uapi.nix — Linux sandbox syscall presence probe
{pkgs, ...}:
pkgs.mkDerivation {
  pname = "sandbox-linux-uapi-probe";
  version = "0";
  src = null;
  buildDeps = [pkgs.linux-headers];
  phases = [
    {
      name = "build";
      script = ''
        $CC -std=c17 -Wall -Wextra -Werror \
          ${../sandbox/linux-uapi-probe.c} -o sandbox-linux-uapi-probe
      '';
    }
    {
      name = "check";
      script = ''
        ./sandbox-linux-uapi-probe > report.json
        grep -q '"missing_count":0' report.json
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin $out/share/aos/sandbox
        cp sandbox-linux-uapi-probe $out/bin/
        cp report.json $out/share/aos/sandbox/linux-uapi-probe.json
      '';
    }
  ];
  meta = {
    description = "Architecture-neutral Linux UAPI probe for AOS sandboxes";
    license = "Apache-2.0";
  };
}
