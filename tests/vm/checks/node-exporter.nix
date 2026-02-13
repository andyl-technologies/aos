{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "node-exporter";
  description = "Prometheus node exporter checks";
  checks = [
    (mkCheck {
      name = "node-exporter-active";
      description = "node-exporter service is active";
      script = ''
        assert_success "systemctl is-active node-exporter" \
          "node-exporter service is active"
      '';
    })
  ];
}
