{
  mkCheck,
  mkCheckGroup,
}:
mkCheckGroup {
  name = "k8s-control-plane";
  description = "Kubernetes control plane configuration (kubeadm, etcd)";
  checks = [
    (mkCheck {
      name = "kubernetes-dir";
      description = "/etc/kubernetes directory exists";
      script = ''
        assert_success "test -d /etc/kubernetes" \
          "/etc/kubernetes directory exists"
      '';
    })
    (mkCheck {
      name = "etcd-dir";
      description = "/var/lib/etcd directory exists";
      script = ''
        assert_success "test -d /var/lib/etcd" \
          "/var/lib/etcd directory exists"
      '';
    })
  ];
}
