##! modules/tests/k8s.nix — Kubernetes component verification checks
##!
##! Verifies that Kubernetes components are properly configured:
##! kubelet, containerd, control plane units (for server), and
##! edgecore (for edge). Checks configuration files, systemd units,
##! and CNI setup. Only active when relevant K8s profiles are enabled.
{ config, lib, ... }:
let
  hasControlPlane = config.aos.profiles.k8s.control.enable or false;
  hasWorker = config.aos.profiles.k8s.worker.enable or false;
  hasEdgecore = config.aos.profiles.k8s.edge.enable or false;
  hasK8s = hasControlPlane || hasWorker || hasEdgecore;
in
{
  config = lib.mkIf hasK8s {
    system.checks.system-k8s = {
      description = "Kubernetes component configuration";
      checks =
        # Containerd checks (both server and edge)
        [
          {
            name = "containerd-unit";
            description = "containerd service unit is installed";
            script = ''
              assert_success "systemctl cat containerd.service" "containerd.service exists"
            '';
          }
          {
            name = "containerd-config";
            description = "containerd configuration is present";
            script = ''
              assert_success "test -f /etc/containerd/config.toml" "containerd config.toml exists"
            '';
          }
        ]
        # Server-specific: kubelet
        ++ (
          if hasControlPlane || hasWorker then
            [
              {
                name = "kubelet-unit";
                description = "kubelet service unit is installed";
                script = ''
                  assert_success "systemctl cat kubelet.service" "kubelet.service exists"
                '';
              }
              {
                name = "kubelet-config";
                description = "kubelet configuration is present";
                script = ''
                  assert_success "test -f /etc/kubernetes/kubelet-config.yaml" \
                    "kubelet-config.yaml exists"
                '';
              }
            ]
          else
            [ ]
        )
        # Server-specific: control plane
        ++ (
          if hasControlPlane then
            [
              {
                name = "kubernetes-config-dir";
                description = "kubernetes configuration directory exists";
                script = ''
                  assert_success "test -d /etc/kubernetes" \
                    "kubernetes config directory exists"
                '';
              }
            ]
          else
            [ ]
        )
        # Edge-specific: edgecore
        ++ (
          if hasEdgecore then
            [
              {
                name = "edgecore-unit";
                description = "edgecore service unit is installed";
                script = ''
                  assert_success "systemctl cat edgecore.service" "edgecore.service exists"
                '';
              }
              {
                name = "edgecore-config";
                description = "edgecore configuration is present";
                script = ''
                  assert_success "test -f /etc/kubeedge/config/edgecore.yaml" \
                    "edgecore.yaml exists"
                '';
              }
            ]
          else
            [ ]
        )
        # CNI configuration (server only)
        ++ (
          if hasControlPlane || hasWorker then
            [
              {
                name = "cni-config-dir";
                description = "CNI configuration directory exists";
                script = ''
                  assert_success "test -d /etc/cni/net.d" "CNI config directory exists"
                '';
              }
            ]
          else
            [ ]
        );
    };
  };
}
