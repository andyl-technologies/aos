##! Source-built test launcher for the Network workers' kernel startup guard.
{
  mkDerivation,
  version,
}:
mkDerivation {
  pname = "aos-network-no-setid-test-launcher";
  inherit version;
  src = ../../../crates/aos-sandbox-network/tests/no_setid_exec.c;
  buildDeps = [];
  runtimeDeps = [];
  phases = [
    {
      name = "build";
      script = ''
        $CC -O2 -Wall -Wextra -Werror "$src" -o no-setid-exec
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        cp no-setid-exec "$out/bin/no-setid-exec"
      '';
    }
  ];
}
