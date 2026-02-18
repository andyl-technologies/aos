# tests/vm/checks/ci-networking.nix — Cloud-init static IP networking
{lib}:
  lib.mkCheckGroup {
    name = "ci-networking";
    description = "Cloud-init static IP configuration";
    checks = [
      (lib.mkCheck {
        name = "networkd-file";
        description = "Static network config file exists";
        script = ''
          TRIES=0
          while [ $TRIES -lt 30 ]; do
            RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
            EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
            if [ "$EXIT_CODE" = "0" ]; then break; fi
            TRIES=$((TRIES + 1))
            sleep 2
          done
          assert_success "test -f /etc/systemd/network/10-eth0.network" \
            "networkd config for eth0 exists"
        '';
      })
      (lib.mkCheck {
        name = "has-address";
        description = "Network config contains static address";
        script = ''
          assert_output_contains "cat /etc/systemd/network/10-eth0.network" "10.0.0.5/24" \
            "Network config has address 10.0.0.5/24"
        '';
      })
      (lib.mkCheck {
        name = "has-gateway";
        description = "Network config contains gateway";
        script = ''
          assert_output_contains "cat /etc/systemd/network/10-eth0.network" "10.0.0.1" \
            "Network config has gateway 10.0.0.1"
        '';
      })
      (lib.mkCheck {
        name = "has-dns";
        description = "Network config contains DNS";
        script = ''
          assert_output_contains "cat /etc/systemd/network/10-eth0.network" "10.0.0.1" \
            "Network config has DNS 10.0.0.1"
        '';
      })
    ];
  }
