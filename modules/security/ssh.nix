##! Selects and verifies the package-owned OpenSSH service.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.services.ssh or {enable = false;};
in {
  environment.systemPackages = [pkgs.openssh];

  aos.pam.services.sshd = lib.mkIf (cfg.enable && cfg.usePAM) {
    unixAuth = cfg.passwordAuthentication;
    startSession = true;
  };

  aos.firewall.allowedTCP = lib.mkIf cfg.enable [cfg.port];

  system.checks.ssh = lib.mkIf cfg.enable {
    description = "SSH server checks";
    checks = [
      {
        name = "sshd-active";
        description = "sshd service is active";
        script = ''
          vm.succeed("systemctl is-active sshd")
        '';
      }
      {
        name = "sshd-config";
        description = "sshd_config exists";
        script = ''
          vm.succeed("test -f /etc/ssh/sshd_config")
        '';
      }
      {
        name = "password-auth-disabled";
        description = "Password authentication is disabled";
        script = ''
          assert "PasswordAuthentication no" in vm.succeed("cat /etc/ssh/sshd_config")
        '';
      }
      {
        name = "sshd-use-pam";
        description = "sshd is configured to use PAM";
        script = ''
          assert "UsePAM ${
            if cfg.usePAM
            then "yes"
            else "no"
          }" in vm.succeed("cat /etc/ssh/sshd_config")
        '';
      }
      {
        name = "sshd-pam-config";
        description = "/etc/pam.d/sshd is present";
        script = ''
          vm.succeed("test -f /etc/pam.d/sshd")
        '';
      }
      {
        name = "sshd-pam-env-rule";
        description = "sshd PAM session stack invokes pam_env";
        script = ''
          assert "pam_env.so" in vm.succeed("cat /etc/pam.d/sshd")
        '';
      }
      {
        name = "pam-environment-has-path";
        description = "/etc/pam/environment publishes PATH";
        script = ''
          assert "PATH" in vm.succeed("cat /etc/pam/environment")
        '';
      }
      {
        name = "sshd-pam-limits-rule";
        description = "sshd PAM session stack invokes pam_limits";
        script = ''
          assert "pam_limits.so" in vm.succeed("cat /etc/pam.d/sshd")
        '';
      }
      {
        name = "ssh-noninteractive-inherits-path";
        description = "non-interactive ssh inherits the system PATH via pam_env";
        script = ''
          import textwrap

          ssh_output = vm.succeed(
              textwrap.dedent(r"""
                  set -e
                  ${pkgs.openssh}/bin/ssh-keygen -t ed25519 -N "" -f /tmp/aos-test-key -q
                  cat /tmp/aos-test-key.pub > /etc/ssh/authorized_keys/root
                  systemctl is-active --quiet sshd || systemctl start sshd
                  ${pkgs.openssh}/bin/ssh -i /tmp/aos-test-key \
                    -o StrictHostKeyChecking=no \
                    -o UserKnownHostsFile=/dev/null \
                    -o BatchMode=yes \
                    -o LogLevel=ERROR \
                    root@127.0.0.1 'echo $PATH'
              """).strip()
          )
          assert "${config.system.build.systemPath}" in ssh_output, (
              f"non-interactive ssh PATH missing expected entries: {ssh_output!r}"
          )
        '';
      }
    ];
  };
}
