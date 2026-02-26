# tests/vm/checks/ci-firewall-k8s-cp.nix — Cloud-init k8s control plane firewall
{lib}:
  lib.mkCheckGroup {
    name = "ci-firewall-k8s-cp";
    description = "Cloud-init k8s control plane firewall rules";
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
        name = "api-server-port";
        description = "Firewall allows API server (6443)";
        script = ''
          assert_output_contains "cat /etc/nftables.conf" "6443" \
            "nftables.conf contains API server port 6443"
        '';
      })
      (lib.mkCheck {
        name = "etcd-ports";
        description = "Firewall allows etcd (2379, 2380)";
        script = ''
          assert_output_contains "cat /etc/nftables.conf" "2379" \
            "nftables.conf contains etcd port 2379"
        '';
      })
      (lib.mkCheck {
        name = "scheduler-port";
        description = "Firewall allows scheduler (10259)";
        script = ''
          assert_output_contains "cat /etc/nftables.conf" "10259" \
            "nftables.conf contains scheduler port 10259"
        '';
      })
      (lib.mkCheck {
        name = "controller-port";
        description = "Firewall allows controller-manager (10257)";
        script = ''
          assert_output_contains "cat /etc/nftables.conf" "10257" \
            "nftables.conf contains controller-manager port 10257"
        '';
      })
      (lib.mkCheck {
        name = "worker-ports-too";
        description = "Control plane also has worker ports";
        script = ''
          assert_output_contains "cat /etc/nftables.conf" "10250" \
            "nftables.conf includes worker kubelet port"
        '';
      })
    ];
  }
