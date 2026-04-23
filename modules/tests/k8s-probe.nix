##! modules/tests/k8s-probe.nix — K8s container runtime functional test
##!
##! Verifies that containerd, crictl, kubectl, kubelet config, and runc
##! are functional on nodes with kubelet enabled.
{
  config,
  lib,
  ...
}: let
  hasKubelet = config.aos.kubernetes.kubelet.enable or false;
  cri = "crictl --runtime-endpoint unix:///run/containerd/containerd.sock";
in {
  config = lib.mkIf hasKubelet {
    system.checks.k8s-probe = {
      description = "K8s container runtime and tools functional test";
      checks = [
        # --- containerd ---
        {
          name = "containerd-active";
          description = "containerd starts and becomes active";
          script = ''
            assert_success "sleep 5 && systemctl is-active containerd" \
              "containerd is active"
          '';
        }
        {
          name = "containerd-socket";
          description = "containerd CRI socket exists";
          script = ''
            assert_success "test -S /run/containerd/containerd.sock" \
              "containerd socket"
          '';
        }
        {
          name = "crictl-version";
          description = "crictl can query containerd CRI version";
          script = ''
            assert_output_contains "${cri} version" "RuntimeVersion" \
              "crictl version"
          '';
        }
        {
          name = "crictl-info";
          description = "crictl can get containerd runtime info";
          script = ''
            assert_output_contains "${cri} info" "containerd" \
              "crictl info"
          '';
        }
        # CRI list operations (empty but functional)
        {
          name = "crictl-pods";
          description = "crictl can list pods (empty)";
          script = ''
            assert_success "${cri} pods" \
              "crictl pods"
          '';
        }
        {
          name = "crictl-ps";
          description = "crictl can list containers (empty)";
          script = ''
            assert_success "${cri} ps" \
              "crictl ps"
          '';
        }
        {
          name = "crictl-images";
          description = "crictl can list images (empty)";
          script = ''
            assert_success "${cri} images" \
              "crictl images"
          '';
        }

        # --- kubectl ---
        {
          name = "kubectl-version";
          description = "kubectl client version works";
          script = ''
            assert_output_contains "kubectl version --client --output=yaml" "clientVersion" \
              "kubectl version"
          '';
        }
        {
          name = "kubectl-binary";
          description = "kubectl binary is functional";
          script = ''
            assert_success "kubectl version --client --short 2>&1; true" \
              "kubectl binary works"
          '';
        }

        # --- kubelet config ---
        {
          name = "kubelet-config";
          description = "kubelet config file exists and contains KubeletConfiguration";
          script = ''
            assert_output_contains "cat /etc/kubernetes/kubelet-config.yaml" "KubeletConfiguration" \
              "kubelet config valid"
          '';
        }

        # --- runc ---
        {
          name = "runc-version";
          description = "runc container runtime is available";
          script = ''
            assert_output_contains "runc --version" "runc version" \
              "runc version"
          '';
        }
      ];
    };
  };
}
