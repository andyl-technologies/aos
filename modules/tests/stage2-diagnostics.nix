##! modules/tests/stage2-diagnostics.nix — one-shot stage-2 diagnostics
##!
##! Dumps `systemctl --failed` + a short journal tail for each known-
##! flaky stage-2 service to the serial console once the system
##! reaches multi-user.target. Gated behind `aos.tests.stage2Diagnostics`
##! so it only pulls in on test builds.
##!
##! Remove this module once the listed services are stable.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.tests.stage2Diagnostics;
  svcs = [
    "sshd.service"
    "sshd-keygen.service"
    "systemd-logind.service"
    "nftables.service"
    "auditd.service"
    "audit-rules.service"
    "k8s-modules-load.service"
    "containerd.service"
    "kubelet.service"
    "dbus.service"
    "dbus.socket"
  ];
in {
  options.aos.tests.stage2Diagnostics.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = ''
      Dump systemctl --failed and per-service journal tails to the
      serial console shortly after multi-user.target is reached.
      Test-only; remove from production images.
    '';
  };

  config = lib.mkIf cfg.enable {
    systemd.services."stage2-diagnostics" = {
      description = "Dump Stage-2 Failure Diagnostics";
      wantedBy = ["multi-user.target"];
      after = ["multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        echo "==================== stage2-diagnostics ===================="
        echo "--- systemctl --failed ---"
        ${pkgs.systemd}/bin/systemctl --failed --no-pager || true
        echo

        echo "--- ls -la /etc/ssh ---"
        ${pkgs.coreutils}/bin/ls -la /etc/ssh/ || true
        echo "--- ls -la /var/etc/ssh ---"
        ${pkgs.coreutils}/bin/ls -la /var/etc/ssh/ || true
        echo "--- stat symlink target for ssh_host_ed25519_key ---"
        ${pkgs.coreutils}/bin/readlink /etc/ssh/ssh_host_ed25519_key || true
        ${pkgs.coreutils}/bin/stat -L /etc/ssh/ssh_host_ed25519_key 2>&1 || true
        echo

        ${lib.concatMapStringsSep "\n" (u: ''
          echo "--- status ${u} ---"
          ${pkgs.systemd}/bin/systemctl status --no-pager --lines=0 ${u} || true
          echo "--- journalctl -u ${u} (last 30 lines) ---"
          ${pkgs.systemd}/bin/journalctl --no-pager --lines=30 -u ${u} || true
          echo
        '') svcs}
        echo "==================== end stage2-diagnostics ================"
      '';
    };
  };
}
