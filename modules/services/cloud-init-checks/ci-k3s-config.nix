# tests/vm/checks/ci-k3s-config.nix — K3s advanced config (labels, mirrors)
{ lib }:
lib.mkCheckGroup {
  name = "ci-k3s-config";
  description = "Cloud-init k3s advanced configuration (labels, registry mirrors)";
  checks = [
    (lib.mkCheck {
      name = "boot-finished";
      description = "Cloud-init completed";
      script = ''
        TRIES=0
        while [ $TRIES -lt 30 ]; do
          RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
          EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
          if [ "$EXIT_CODE" = "0" ]; then break; fi
          TRIES=$((TRIES + 1))
          sleep 2
        done
        assert_success "test -f /var/lib/cloud/state/boot-finished" \
          "cloud-init completed"
      '';
    })
    (lib.mkCheck {
      name = "node-labels";
      description = "K3s config has node labels";
      script = ''
        assert_output_contains "cat /etc/rancher/k3s/config.yaml" "node-label" \
          "k3s config has node-label section"
      '';
    })
    (lib.mkCheck {
      name = "label-zone";
      description = "K3s config has zone label";
      script = ''
        assert_output_contains "cat /etc/rancher/k3s/config.yaml" "topology.kubernetes.io/zone=us-east-1a" \
          "k3s config has zone label"
      '';
    })
    (lib.mkCheck {
      name = "label-pool";
      description = "K3s config has pool label";
      script = ''
        assert_output_contains "cat /etc/rancher/k3s/config.yaml" "node.kubernetes.io/pool=workers" \
          "k3s config has pool label"
      '';
    })
    (lib.mkCheck {
      name = "registry-mirror";
      description = "Containerd config has registry mirror";
      script = ''
        assert_output_contains "cat /etc/containerd/config.toml" "docker.io" \
          "containerd config has docker.io mirror"
      '';
    })
    (lib.mkCheck {
      name = "mirror-endpoint";
      description = "Registry mirror has correct endpoint";
      script = ''
        assert_output_contains "cat /etc/containerd/config.toml" "mirror.internal" \
          "containerd config has mirror endpoint"
      '';
    })
  ];
}
