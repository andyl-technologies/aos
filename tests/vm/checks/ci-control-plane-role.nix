# tests/vm/checks/ci-control-plane-role.nix — K8s control plane role via cloud-init
{lib}:
  lib.mkCheckGroup {
    name = "ci-control-plane-role";
    description = "Cloud-init k8s-control-plane role configuration";
    checks = [
      (lib.mkCheck {
        name = "role-marker";
        description = "Active role is 'k8s-control-plane'";
        script = ''
          TRIES=0
          while [ $TRIES -lt 30 ]; do
            RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
            EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
            if [ "$EXIT_CODE" = "0" ]; then break; fi
            TRIES=$((TRIES + 1))
            sleep 2
          done
          assert_output_contains "cat /var/lib/cloud/state/active-role" "k8s-control-plane" \
            "Active role is k8s-control-plane"
        '';
      })
      (lib.mkCheck {
        name = "k3s-server-config";
        description = "K3s server config.yaml exists";
        script = ''
          assert_success "test -f /etc/rancher/k3s/config.yaml" \
            "k3s server config.yaml exists"
        '';
      })
      (lib.mkCheck {
        name = "cluster-init";
        description = "K3s config has cluster-init";
        script = ''
          assert_output_contains "cat /etc/rancher/k3s/config.yaml" "cluster-init: true" \
            "k3s config has cluster-init"
        '';
      })
      (lib.mkCheck {
        name = "disable-kube-proxy";
        description = "K3s config disables kube-proxy";
        script = ''
          assert_output_contains "cat /etc/rancher/k3s/config.yaml" "disable-kube-proxy: true" \
            "k3s config disables kube-proxy"
        '';
      })
      (lib.mkCheck {
        name = "cluster-cidr";
        description = "K3s config has cluster CIDR";
        script = ''
          assert_output_contains "cat /etc/rancher/k3s/config.yaml" "cluster-cidr: 10.244.0.0/16" \
            "k3s config has cluster CIDR"
        '';
      })
      (lib.mkCheck {
        name = "tls-san";
        description = "K3s config has TLS SAN";
        script = ''
          assert_output_contains "cat /etc/rancher/k3s/config.yaml" "10.0.0.10" \
            "k3s config has TLS SAN entry"
        '';
      })
      (lib.mkCheck {
        name = "containerd-config";
        description = "Containerd config exists for control plane";
        script = ''
          assert_success "test -f /etc/containerd/config.toml" \
            "containerd config.toml exists"
        '';
      })
    ];
  }
