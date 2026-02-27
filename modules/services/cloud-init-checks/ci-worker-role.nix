# tests/vm/checks/ci-worker-role.nix — K8s worker role via cloud-init
{lib}:
lib.mkCheckGroup {
  name = "ci-worker-role";
  description = "Cloud-init k8s-worker role configuration";
  checks = [
    (lib.mkCheck {
      name = "role-marker";
      description = "Active role is 'k8s-worker'";
      script = ''
        TRIES=0
        while [ $TRIES -lt 30 ]; do
          RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
          EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
          if [ "$EXIT_CODE" = "0" ]; then break; fi
          TRIES=$((TRIES + 1))
          sleep 2
        done
        assert_output_contains "cat /var/lib/cloud/state/active-role" "k8s-worker" \
          "Active role is k8s-worker"
      '';
    })
    (lib.mkCheck {
      name = "containerd-config";
      description = "Containerd config.toml exists";
      script = ''
        assert_success "test -f /etc/containerd/config.toml" \
          "containerd config.toml exists"
      '';
    })
    (lib.mkCheck {
      name = "k3s-agent-config";
      description = "K3s agent config.yaml exists";
      script = ''
        assert_success "test -f /etc/rancher/k3s/config.yaml" \
          "k3s config.yaml exists"
      '';
    })
    (lib.mkCheck {
      name = "k3s-server-url";
      description = "K3s config has server URL";
      script = ''
        assert_output_contains "cat /etc/rancher/k3s/config.yaml" "server: https://10.0.0.10:6443" \
          "k3s config has server URL"
      '';
    })
    (lib.mkCheck {
      name = "k3s-agent-unit";
      description = "K3s agent systemd unit file exists";
      script = ''
        assert_success "test -f /etc/systemd/system/k3s-agent.service" \
          "k3s-agent.service unit exists"
      '';
    })
  ];
}
