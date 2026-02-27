# tests/vm/checks/ci-k8s-net-prereqs.nix — Kubernetes networking prerequisites
{lib}:
lib.mkCheckGroup {
  name = "ci-k8s-net-prereqs";
  description = "Cloud-init k8s networking kernel prerequisites";
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
      name = "modules-load-conf";
      description = "modules-load.d/k8s.conf exists";
      script = ''
        assert_success "test -f /etc/modules-load.d/k8s.conf" \
          "k8s kernel modules config exists"
      '';
    })
    (lib.mkCheck {
      name = "br-netfilter-module";
      description = "br_netfilter listed in modules config";
      script = ''
        assert_output_contains "cat /etc/modules-load.d/k8s.conf" "br_netfilter" \
          "br_netfilter in modules-load.d"
      '';
    })
    (lib.mkCheck {
      name = "overlay-module";
      description = "overlay listed in modules config";
      script = ''
        assert_output_contains "cat /etc/modules-load.d/k8s.conf" "overlay" \
          "overlay in modules-load.d"
      '';
    })
    (lib.mkCheck {
      name = "sysctl-conf";
      description = "sysctl.d/90-k8s.conf exists";
      script = ''
        assert_success "test -f /etc/sysctl.d/90-k8s.conf" \
          "k8s sysctl config exists"
      '';
    })
    (lib.mkCheck {
      name = "ip-forward-sysctl";
      description = "sysctl config has ip_forward";
      script = ''
        assert_output_contains "cat /etc/sysctl.d/90-k8s.conf" "net.ipv4.ip_forward" \
          "sysctl has ip_forward"
      '';
    })
    (lib.mkCheck {
      name = "bridge-nf-sysctl";
      description = "sysctl config has bridge-nf-call-iptables";
      script = ''
        assert_output_contains "cat /etc/sysctl.d/90-k8s.conf" "bridge-nf-call-iptables" \
          "sysctl has bridge-nf-call-iptables"
      '';
    })
  ];
}
