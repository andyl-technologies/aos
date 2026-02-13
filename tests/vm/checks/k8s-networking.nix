{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "k8s-networking";
  description = "Kubernetes network prerequisites checks";
  checks = [
    (mkCheck {
      name = "ip-forward";
      description = "IP forwarding is enabled";
      script = ''
        assert_output_contains "cat /proc/sys/net/ipv4/ip_forward" "1" \
          "IP forwarding is enabled"
      '';
    })
    (mkCheck {
      name = "bridge-nf-call";
      description = "Bridge netfilter call is enabled";
      script = ''
        assert_output_contains "cat /proc/sys/net/bridge/bridge-nf-call-iptables" "1" \
          "Bridge netfilter call is enabled"
      '';
    })
  ];
}
