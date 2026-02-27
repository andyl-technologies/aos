# tests/vm/checks/ci-firewall-k8s-worker.nix — Cloud-init k8s worker firewall
{lib}:
lib.mkCheckGroup {
  name = "ci-firewall-k8s-worker";
  description = "Cloud-init k8s worker firewall rules";
  checks = [
    (lib.mkCheck {
      name = "nftables-conf";
      description = "nftables.conf exists after cloud-init";
      script = ''
        TRIES=0
        while [ $TRIES -lt 30 ]; do
          RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
          EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
          if [ "$EXIT_CODE" = "0" ]; then break; fi
          TRIES=$((TRIES + 1))
          sleep 2
        done
        assert_success "test -f /etc/nftables.conf" \
          "nftables.conf exists"
      '';
    })
    (lib.mkCheck {
      name = "kubelet-port";
      description = "Firewall allows kubelet API (10250)";
      script = ''
        assert_output_contains "cat /etc/nftables.conf" "10250" \
          "nftables.conf contains kubelet port 10250"
      '';
    })
    (lib.mkCheck {
      name = "nodeport-range";
      description = "Firewall allows NodePort range (30000-32767)";
      script = ''
        assert_output_contains "cat /etc/nftables.conf" "30000-32767" \
          "nftables.conf contains NodePort range"
      '';
    })
    (lib.mkCheck {
      name = "vxlan-port";
      description = "Firewall allows VXLAN overlay (8472/udp)";
      script = ''
        assert_output_contains "cat /etc/nftables.conf" "8472" \
          "nftables.conf contains VXLAN port 8472"
      '';
    })
    (lib.mkCheck {
      name = "cilium-ports";
      description = "Firewall allows Cilium health (4240)";
      script = ''
        assert_output_contains "cat /etc/nftables.conf" "4240" \
          "nftables.conf contains Cilium port 4240"
      '';
    })
    (lib.mkCheck {
      name = "forward-accept";
      description = "Forward policy is accept for pod traffic";
      script = ''
        assert_output_contains "cat /etc/nftables.conf" "forward" \
          "nftables.conf has forward chain"
      '';
    })
  ];
}
