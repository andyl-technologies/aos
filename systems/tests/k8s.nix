# systems/tests/k8s.nix — Kubernetes component verification
#
# Verifies that Kubernetes components are properly configured:
# kubelet, containerd, control plane units (for server), and
# edgecore (for edge). Checks configuration files, systemd units,
# and CNI setup.
{ lib }:
{
  name = "k8s";
  description = "Kubernetes component configuration";
  type = "vm";
  appliesTo = [
    "server"
    "edge"
  ];

  checks =
    { config, lib }:
    let
      isServer = config.aos.profiles.server.enable or false;
      isEdge = config.aos.profiles.edge.enable or false;
      hasControlPlane = config.aos.profiles.k8s.control.enable or false;
      hasWorker = config.aos.profiles.k8s.worker.enable or false;
      hasEdgecore = config.aos.profiles.k8s.edge.enable or false;
    in
    # Containerd checks (both server and edge)
    [
      (lib.mkCheck {
        name = "containerd-unit";
        description = "containerd service unit is installed";
        script = ''
          assert_success "systemctl cat containerd.service" "containerd.service exists"
        '';
      })
      (lib.mkCheck {
        name = "containerd-config";
        description = "containerd configuration is present";
        script = ''
          assert_success "test -f /etc/containerd/config.toml" "containerd config.toml exists"
        '';
      })
    ]
    # Server-specific: kubelet
    ++ (
      if hasControlPlane || hasWorker then
        [
          (lib.mkCheck {
            name = "kubelet-unit";
            description = "kubelet service unit is installed";
            script = ''
              assert_success "systemctl cat kubelet.service" "kubelet.service exists"
            '';
          })
          (lib.mkCheck {
            name = "kubelet-config";
            description = "kubelet configuration is present";
            script = ''
              assert_success "test -f /etc/kubernetes/kubelet-config.yaml" \
                "kubelet-config.yaml exists"
            '';
          })
        ]
      else
        [ ]
    )
    # Server-specific: control plane
    ++ (
      if hasControlPlane then
        [
          (lib.mkCheck {
            name = "kubernetes-config-dir";
            description = "kubernetes configuration directory exists";
            script = ''
              assert_success "test -d /etc/kubernetes" \
                "kubernetes config directory exists"
            '';
          })
        ]
      else
        [ ]
    )
    # Edge-specific: edgecore
    ++ (
      if hasEdgecore then
        [
          (lib.mkCheck {
            name = "edgecore-unit";
            description = "edgecore service unit is installed";
            script = ''
              assert_success "systemctl cat edgecore.service" "edgecore.service exists"
            '';
          })
          (lib.mkCheck {
            name = "edgecore-config";
            description = "edgecore configuration is present";
            script = ''
              assert_success "test -f /etc/kubeedge/config/edgecore.yaml" \
                "edgecore.yaml exists"
            '';
          })
        ]
      else
        [ ]
    )
    # CNI configuration (server only)
    ++ (
      if hasControlPlane || hasWorker then
        [
          (lib.mkCheck {
            name = "cni-config-dir";
            description = "CNI configuration directory exists";
            script = ''
              assert_success "test -d /etc/cni/net.d" "CNI config directory exists"
            '';
          })
        ]
      else
        [ ]
    );
}
