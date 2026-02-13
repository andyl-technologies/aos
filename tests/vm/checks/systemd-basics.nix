{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "systemd-basics";
  description = "systemd service infrastructure checks";
  checks = [
    (mkCheck {
      name = "runtime-dir";
      description = "systemd runtime directory exists";
      script = ''
        assert_success "test -d /run/systemd/system" \
          "systemd runtime directory exists"
      '';
    })
    (mkCheck {
      name = "timers";
      description = "systemd timers are functional";
      script = ''
        assert_success "systemctl list-timers --no-pager" \
          "systemd timers are functional"
      '';
    })
    (mkCheck {
      name = "list-services";
      description = "systemctl can list services";
      script = ''
        assert_success "systemctl list-units --type=service --no-pager" \
          "systemctl can list services"
      '';
    })
    (mkCheck {
      name = "journal";
      description = "journalctl can read system journal";
      script = ''
        assert_success "journalctl --no-pager -n 5" \
          "journalctl can read system journal"
      '';
    })
    (mkCheck {
      name = "etc-writable";
      description = "/etc is writable for updates";
      script = ''
        assert_success "touch /etc/test-write && rm /etc/test-write" \
          "/etc is writable for updates"
      '';
    })
  ];
}
