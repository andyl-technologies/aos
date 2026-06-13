##! modules/roles/aos-test-agent.nix — Test guest agent as a role, for
##! image-boot fleet machines.
##!
##! Kernel/initrd-boot test machines get the agent injected into their
##! test disk by `lib/testing/vm.nix` (mkTestDisk's postPopulate).
##! Image-boot machines (tests/fleet/install-from-image.nix) boot the
##! production image — UEFI → sd-boot → UKI → ignition — so the agent
##! must arrive the way any production payload does: as a bundled role
##! whose ignition fragment the harness merges at first boot. The
##! script bytes are shared with the test-disk path
##! (`lib/testing/agent/aos-test-agent.sh`) — one source of truth for
##! the agent wire protocol.
##!
##! The service is `After=multi-user.target` while also being wanted
##! by it, so the agent answers its first PING only once the boot has
##! conceptually completed — mirroring the aos-test.target ordering
##! trick in lib/testing/vm.nix's varSeed.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.roles.aos-test-agent;

  agentBin = pkgs.writeTextFile {
    name = "aos-test-agent";
    executable = true;
    destination = "/bin/aos-test-agent";
    text = builtins.readFile ../../lib/testing/agent/aos-test-agent.sh;
  };
in {
  config = lib.mkMerge [
    {
      aos.roles.aos-test-agent = {
        systemd.services.aos-test-agent = {
          description = "AOS VM test guest agent (virtio-serial)";
          after = ["multi-user.target"];
          wants = ["multi-user.target"];
          wantedBy = ["multi-user.target"];

          serviceConfig = {
            ExecStart = "${agentBin}/bin/aos-test-agent";
            Restart = "on-failure";
            RestartSec = "1";
            # The production image has no merged /usr/bin — every tool
            # lives at its own store path. The agent script appends the
            # inherited PATH after the FHS dirs, so this Environment=
            # is what actually resolves coreutils (head/stat/mkfifo/
            # tee/sleep), bash, and reboot/poweroff (systemd sbin) on
            # image-boot machines.
            Environment = "PATH=${pkgs.coreutils}/bin:${pkgs.bash}/bin:${pkgs.systemd}/bin:${pkgs.systemd}/sbin";
          };
        };
      };
    }

    (lib.mkIf cfg.bundle {
      # ExecStart references the agent's store path; the closure must
      # carry it (ignition writes the unit but can't materialize store
      # paths). bash/coreutils ride the base system already.
      environment.systemPackages = [agentBin];
    })
  ];
}
