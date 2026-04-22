# tests/vm/checks/ci-hostname.nix — Cloud-init hostname configuration
{ lib }:
{
  description = "Cloud-init hostname configuration";
  checks = [
    {
      name = "hostname-file";
      description = "Hostname written to /etc/hostname";
      script = ''
        # Wait for cloud-init to complete
        TRIES=0
        while [ $TRIES -lt 30 ]; do
          RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
          EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
          if [ "$EXIT_CODE" = "0" ]; then break; fi
          TRIES=$((TRIES + 1))
          sleep 2
        done
        assert_output_contains "cat /etc/hostname" "test-webserver" \
          "Hostname is test-webserver"
      '';
    }
  ];
}
