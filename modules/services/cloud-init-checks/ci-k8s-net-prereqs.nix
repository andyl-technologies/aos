# tests/vm/checks/ci-k8s-net-prereqs.nix — Kubernetes networking prerequisites
{ lib }:
{
  description = "Cloud-init k8s networking kernel prerequisites";
  checks = [
    {
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
    }
    {
      name = "modules-load-conf";
      description = "modules-load.d/k8s.conf exists";
      script = ''
        assert_success "test -f /etc/modules-load.d/k8s.conf" \
          "k8s kernel modules config exists"
      '';
    }
    {
      name = "br-netfilter-module";
      description = "br_netfilter listed in modules config";
      script = ''
        assert_output_contains "cat /etc/modules-load.d/k8s.conf" "br_netfilter" \
          "br_netfilter in modules-load.d"
      '';
    }
    {
      name = "overlay-module";
      description = "overlay listed in modules config";
      script = ''
        assert_output_contains "cat /etc/modules-load.d/k8s.conf" "overlay" \
          "overlay in modules-load.d"
      '';
    }
    {
      name = "sysctl-conf";
      description = "sysctl.d/90-k8s.conf exists";
      script = ''
        assert_success "test -f /etc/sysctl.d/90-k8s.conf" \
          "k8s sysctl config exists"
      '';
    }
    {
      name = "ip-forward-sysctl";
      description = "sysctl config has ip_forward";
      script = ''
        assert_output_contains "cat /etc/sysctl.d/90-k8s.conf" "net.ipv4.ip_forward" \
          "sysctl has ip_forward"
      '';
    }
    {
      name = "bridge-nf-sysctl";
      description = "sysctl config has bridge-nf-call-iptables";
      script = ''
        assert_output_contains "cat /etc/sysctl.d/90-k8s.conf" "bridge-nf-call-iptables" \
          "sysctl has bridge-nf-call-iptables"
      '';
    }
  ];
}
