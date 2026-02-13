{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "containerd";
  description = "Container runtime checks";
  checks = [
    (mkCheck {
      name = "containerd-active";
      description = "containerd service is active";
      script = ''
        assert_success "systemctl is-active containerd" \
          "containerd service is active"
      '';
    })
    (mkCheck {
      name = "containerd-socket";
      description = "containerd socket exists";
      script = ''
        assert_success "test -S /run/containerd/containerd.sock" \
          "containerd socket exists"
      '';
    })
    (mkCheck {
      name = "containerd-config";
      description = "containerd config.toml exists";
      script = ''
        assert_success "test -f /etc/containerd/config.toml" \
          "containerd config.toml exists"
      '';
    })
  ];
}
