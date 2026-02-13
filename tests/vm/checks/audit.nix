{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "audit";
  description = "Audit daemon checks";
  checks = [
    (mkCheck {
      name = "auditd-active";
      description = "auditd service is active";
      script = ''
        assert_success "systemctl is-active auditd" \
          "auditd service is active"
      '';
    })
    (mkCheck {
      name = "audit-rules";
      description = "Audit rules file exists";
      script = ''
        assert_success "test -f /etc/audit/audit.rules" \
          "Audit rules file exists"
      '';
    })
  ];
}
