{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "kubelet";
  description = "Kubelet and CNI checks";
  checks = [
    (mkCheck {
      name = "kubelet-enabled";
      description = "kubelet service is enabled";
      script = ''
        assert_success "systemctl is-enabled kubelet" \
          "kubelet service is enabled"
      '';
    })
    (mkCheck {
      name = "kubelet-config";
      description = "kubelet config.yaml exists";
      script = ''
        assert_success "test -f /var/lib/kubelet/config.yaml" \
          "kubelet config.yaml exists"
      '';
    })
    (mkCheck {
      name = "cni-dir";
      description = "CNI config directory exists";
      script = ''
        assert_success "test -d /etc/cni/net.d" \
          "CNI config directory exists"
      '';
    })
  ];
}
