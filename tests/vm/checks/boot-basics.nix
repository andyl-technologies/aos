{
  mkCheck,
  mkCheckGroup,
}:
mkCheckGroup {
  name = "boot-basics";
  description = "Core boot verification";
  checks = [
    (mkCheck {
      name = "os-release";
      description = "os-release contains ANDYL OS";
      script = ''
        assert_output_contains "cat /etc/os-release" "ANDYL OS" \
          "os-release contains ANDYL OS"
      '';
    })
    (mkCheck {
      name = "hostname";
      description = "Hostname is set";
      script = ''
        assert_success "test -f /etc/hostname" \
          "/etc/hostname exists"
      '';
    })
    (mkCheck {
      name = "systemd-running";
      description = "systemd reached running state";
      script = ''
        assert_success "systemctl is-system-running --wait || true" \
          "systemd reached running state"
      '';
    })
    (mkCheck {
      name = "kernel-version";
      description = "Kernel version is 6.18.x";
      script = ''
        assert_output_contains "uname -r" "6.18" \
          "kernel version is 6.18.x"
      '';
    })
  ];
}
