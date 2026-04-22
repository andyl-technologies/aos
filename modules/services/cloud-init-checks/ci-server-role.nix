# tests/vm/checks/ci-server-role.nix — Full server role via cloud-init
{ lib }:
{
  description = "Cloud-init server role full configuration";
  checks = [
    {
      name = "role-marker";
      description = "Active role is 'server'";
      script = ''
        TRIES=0
        while [ $TRIES -lt 30 ]; do
          RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
          EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
          if [ "$EXIT_CODE" = "0" ]; then break; fi
          TRIES=$((TRIES + 1))
          sleep 2
        done
        assert_output_contains "cat /var/lib/cloud/state/active-role" "server" \
          "Active role is server"
      '';
    }
    {
      name = "sshd-active";
      description = "SSH is active";
      script = ''
        assert_success "systemctl is-active sshd" \
          "sshd is active"
      '';
    }
    {
      name = "nftables-active";
      description = "nftables is active";
      script = ''
        assert_success "systemctl is-active nftables" \
          "nftables is active"
      '';
    }
    {
      name = "chrony-active";
      description = "chronyd is active";
      script = ''
        TRIES=0
        while [ $TRIES -lt 15 ]; do
          RESULT=$(run_in_guest "systemctl is-active chronyd" 2>/dev/null || true)
          STATUS=$(echo "$RESULT" | jq -r '.stdout // empty' 2>/dev/null || echo "$RESULT")
          if [ "$STATUS" = "active" ]; then break; fi
          TRIES=$((TRIES + 1))
          sleep 2
        done
        assert_success "systemctl is-active chronyd" \
          "chronyd is active"
      '';
    }
    {
      name = "no-containerd";
      description = "No containerd config for server role";
      script = ''
        RESULT=$(run_in_guest "test -f /etc/containerd/config.toml")
        EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code')
        if [ "$EXIT_CODE" = "0" ]; then
          echo "FAIL: containerd config should not exist for server role"
          return 1
        fi
        echo "PASS: no containerd config for server role"
      '';
    }
  ];
}
