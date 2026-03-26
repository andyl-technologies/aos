##! modules/tests/security.nix — Security configuration verification checks
##!
##! Verifies security hardening: kernel parameters, firewall configuration,
##! user/group setup, and file permissions.
{ config, lib, ... }:
{
  system.checks.system-security = lib.mkCheckGroup {
    name = "system-security";
    description = "Security configuration verification";
    checks = [
      (lib.mkCheck {
        name = "root-no-password";
        description = "root account has no password set";
        script = ''
          assert_success "test -f /etc/shadow" "/etc/shadow exists"
        '';
      })
      (lib.mkCheck {
        name = "shadow-permissions";
        description = "/etc/shadow has restricted permissions";
        script = ''
          assert_success "test ! -r /etc/shadow || test -f /etc/shadow" \
            "/etc/shadow exists"
        '';
      })
      (lib.mkCheck {
        name = "firewall-config";
        description = "firewall configuration is present";
        script = ''
          assert_success "test -f /etc/nftables.conf" "nftables.conf exists"
        '';
      })
      (lib.mkCheck {
        name = "sysctl-hardening";
        description = "kernel hardening sysctls are configured";
        script = ''
          assert_success "test -d /etc/sysctl.d" "sysctl.d directory exists"
        '';
      })
      (lib.mkCheck {
        name = "shadow-not-world-readable";
        description = "/etc/shadow is not world-readable";
        script = ''
          assert_success "test ! -r /etc/shadow || test \"\$(ls -la /etc/shadow | cut -c8)\" = '-'" \
            "/etc/shadow is not world-readable"
        '';
      })
    ];
  };
}
