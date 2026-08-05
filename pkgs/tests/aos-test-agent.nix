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

    expose = {
      units = {
        "aos-test-agent.service" = {
          description = "AOS VM test guest agent";
          serviceConfig = {
            Type = "simple";
            ExecStart = "${agentBin}/bin/aos-test-agent";
            Restart = "on-failure";
            RestartSec = "1";
            Environment = "PATH=${coreutils}/bin:${bash}/bin:${systemd}/bin:${systemd}/sbin";
          };
        };
      };

      permissions = {
        # The agent is test infrastructure: it opens the QEMU virtio-serial
        # device, runs arbitrary test commands as root, and can power off the
        # VM. Keep that escape hatch explicit in the signed manifest.
        network = "host";
        privileged-users = true;
        syscalls = "privileged";
      };
    };

    # The fleet control plane is test infrastructure rather than image policy.
    # Keep its generated expose module usable on both sides of the RFC-0011
    # ABI-transition acceptance test; config-module-smoke remains the
    # deliberately ABI-1-only negative fixture.
    configModule = {
      src = ./_aos-test-agent-config;
      moduleAbiCompat = {
        min = 1;
        max = 2;
      };
      declares = [];
    };

    meta.description = "AOS exposed package for the VM test guest agent";
  }
