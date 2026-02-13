{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "ssh";
  description = "SSH server checks";
  checks = [
    (mkCheck {
      name = "sshd-active";
      description = "sshd service is active";
      script = ''
        assert_success "systemctl is-active sshd" \
          "sshd service is active"
      '';
    })
    (mkCheck {
      name = "sshd-config";
      description = "sshd_config exists";
      script = ''
        assert_success "test -f /etc/ssh/sshd_config" \
          "sshd_config exists"
      '';
    })
    (mkCheck {
      name = "password-auth-disabled";
      description = "Password authentication is disabled";
      script = ''
        assert_output_contains "cat /etc/ssh/sshd_config" "PasswordAuthentication no" \
          "Password authentication is disabled"
      '';
    })
  ];
}
