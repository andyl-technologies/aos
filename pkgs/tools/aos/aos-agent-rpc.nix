##! aos-agent-rpc — Single-shot RPC client for the AOS VM test agent
{mkDerivation}:
mkDerivation {
  pname = "aos-agent-rpc";
  version = "0";
  src = null;

  phases = [
    {
      name = "build";
      script = ''
        mkdir -p $out/bin
        $CC -O2 -Wall -Wextra -o $out/bin/aos-agent-rpc ${./aos-agent-rpc.c}
      '';
    }
  ];

  meta = {
    description = "Single-shot RPC client for the AOS VM test agent";
    license = "Apache-2.0";
  };
}
