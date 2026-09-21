##! Systemd-specific fleet-machine integration for the generic test harness.
{
  lib,
  packages,
}: {
  bakeAgentUnit,
  debugMac,
  defaultAgentPackage,
  ip,
  mac,
  sshAuthorizedKey ? null,
  writeTextFile,
}: {config, ...}: let
  agentPackage = config.aos.packages.aos-test-agent.package or defaultAgentPackage;
  agentPath = "${agentPackage}/share/aos-test-agent/aos-test-agent";
  runtimeAgentUnit = writeTextFile {
    name = "aos-fleet-test-agent-runtime-unit";
    destination = "/aos-test-agent.service";
    text = ''
      [Unit]
      Description=AOS VM Test Guest Agent
      RefuseManualStop=true

      [Service]
      Type=simple
      ExecStart=${agentPath}
      Restart=on-failure
      RestartSec=1
      Environment=PATH=${packages.coreutils}/bin:${packages.bash}/bin:${packages.systemd}/bin:${packages.systemd}/sbin
    '';
  };
in {
  # Fleet machines have no interactive console. Mask debug shells that would
  # corrupt the serial transport or delay switch-root during test shutdown.
  boot.initrd.systemd.maskedUnits = [
    "debug-shell-console.service"
    "debug-shell-serial.service"
  ];

  # Image boots take their command line from the UKI. Match the direct-kernel
  # test transport and keep predictable interface names.
  aos.boot.kernelParams = [
    "systemd.journald.forward_to_console=1"
    "net.ifnames=0"
  ];

  environment.etc =
    {
      "systemd/network/10-fleet-eth0.network".text = ''
        [Match]
        MACAddress=${mac}

        [Network]
        Address=${ip}/24
      '';
    }
    // lib.optionalAttrs (sshAuthorizedKey != null) {
      "systemd/network/20-debug-eth1.network".text = ''
        [Match]
        MACAddress=${debugMac}

        [Network]
        DHCP=ipv4
      '';
    };

  systemd.services = lib.optionalAttrs bakeAgentUnit {
    "aos-test-agent-bootstrap" = {
      description = "Install the AOS VM test control channel";
      wantedBy = ["multi-user.target"];
      before = ["aos-eval.service"];
      stopOnRemoval = false;
      unitConfig.RefuseManualStop = true;
      serviceConfig.Type = "oneshot";
      script = ''
        ${packages.coreutils}/bin/mkdir -p /run/systemd/system
        ${packages.coreutils}/bin/ln -sfn ${runtimeAgentUnit}/aos-test-agent.service \
          /run/systemd/system/aos-test-agent.service
        ${packages.systemd}/bin/systemctl daemon-reload
        ${packages.systemd}/bin/systemctl start aos-test-agent.service
      '';
    };
  };
}
