{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "networking-base";
  description = "Base networking checks";
  checks = [
    (mkCheck {
      name = "loopback-exists";
      description = "Loopback interface exists";
      script = ''
        assert_success "test -d /sys/class/net/lo" \
          "Loopback interface exists"
      '';
    })
    (mkCheck {
      name = "loopback-up";
      description = "Loopback interface is up";
      script = ''
        assert_output_contains "cat /sys/class/net/lo/operstate" "unknown" \
          "Loopback interface is up"
      '';
    })
    (mkCheck {
      name = "proc-net";
      description = "/proc/net is available";
      script = ''
        assert_success "test -d /proc/net" \
          "/proc/net is available"
      '';
    })
    (mkCheck {
      name = "hostname-file";
      description = "/etc/hostname exists";
      script = ''
        assert_success "test -f /etc/hostname" \
          "/etc/hostname exists"
      '';
    })
  ];
}
