{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "chrony";
  description = "NTP time sync checks";
  checks = [
    (mkCheck {
      name = "chronyd-active";
      description = "chronyd service is active";
      script = ''
        assert_success "systemctl is-active chronyd" \
          "chronyd service is active"
      '';
    })
    (mkCheck {
      name = "chrony-config";
      description = "chrony.conf exists";
      script = ''
        assert_success "test -f /etc/chrony.conf" \
          "chrony.conf exists"
      '';
    })
  ];
}
