{
  mkDerivation,
  writeTextFile,
  bash,
  coreutils,
  systemd,
}: let
  agentBin = writeTextFile {
    name = "aos-test-agent";
    executable = true;
    destination = "/bin/aos-test-agent";
    text = builtins.readFile ../../lib/testing/agent/aos-test-agent.sh;
  };
in
  mkDerivation {
    pname = "aos-test-agent";
    version = "0";
    src = null;

    runtimeDeps = [
      agentBin
      bash
      coreutils
      systemd
    ];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/aos-test-agent"
          ln -s ${agentBin}/bin/aos-test-agent "$out/share/aos-test-agent/aos-test-agent"
        '';
      }
    ];

    abilities = ./_aos-test-agent/module.nix;

    meta = {
      description = "AOS package for the VM test guest agent";
      license = "Apache-2.0";
    };
  }
