{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "update-infra";
  description = "Update/GC/health-check infrastructure checks";
  checks = [
    (mkCheck {
      name = "update-timer";
      description = "Update timer is enabled";
      script = ''
        assert_success "systemctl is-enabled aos-update-check.timer" \
          "Update check timer is enabled"
      '';
    })
    (mkCheck {
      name = "gc-timer";
      description = "GC timer is enabled";
      script = ''
        assert_success "systemctl is-enabled aos-gc.timer" \
          "GC timer is enabled"
      '';
    })
    (mkCheck {
      name = "health-check";
      description = "Health check service unit exists";
      script = ''
        assert_success "systemctl cat aos-health-check.service" \
          "Health check service unit exists"
      '';
    })
  ];
}
