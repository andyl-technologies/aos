# tests/vm/checks/ci-defaults.nix — Cloud-init default boot (no userdata)
#
# Verifies golden image behavior with no userdata: default hostname,
# DHCP networking, SSH active, firewall active, boot-finished marker.
{ lib }:
{
  description = "Cloud-init default boot (no userdata)";
  checks = [
    {
      name = "default-hostname";
      description = "Default hostname is 'aos'";
      script = ''
        assert_output_contains "cat /etc/hostname" "aos" \
          "Default hostname is aos"
      '';
    }
    {
      name = "sshd-active";
      description = "SSH service is active";
      script = ''
        assert_success "systemctl is-active sshd" \
          "sshd is active"
      '';
    }
    {
      name = "nftables-active";
      description = "Firewall is active";
      script = ''
        assert_success "systemctl is-active nftables" \
          "nftables is active"
      '';
    }
    {
      name = "boot-finished";
      description = "Cloud-init wrote boot-finished marker";
      script = ''
        # Cloud-init stages may need a moment to complete
        TRIES=0
        while [ $TRIES -lt 30 ]; do
          RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
          EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
          if [ "$EXIT_CODE" = "0" ]; then
            break
          fi
          TRIES=$((TRIES + 1))
          sleep 2
        done
        assert_success "test -f /var/lib/cloud/state/boot-finished" \
          "boot-finished marker exists"
      '';
    }
    {
      name = "cloud-init-local-done";
      description = "Cloud-init local stage completed";
      script = ''
        assert_success "test -f /var/lib/cloud/state/local-done" \
          "cloud-init local stage completed"
      '';
    }
    {
      name = "no-containerd";
      description = "Containerd is not configured by default";
      script = ''
        RESULT=$(run_in_guest "test -f /etc/containerd/config.toml")
        EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code')
        if [ "$EXIT_CODE" = "0" ]; then
          echo "FAIL: containerd config should not exist in default boot"
          return 1
        fi
        echo "PASS: no containerd config in default boot"
      '';
    }
  ];
}
