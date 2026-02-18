# tests/vm/checks/ci-firewall-server.nix — Cloud-init server firewall rules
{lib}:
  lib.mkCheckGroup {
    name = "ci-firewall-server";
    description = "Cloud-init server role firewall configuration";
    checks = [
      (lib.mkCheck {
        name = "nftables-active";
        description = "nftables is active after cloud-init";
        script = ''
          TRIES=0
          while [ $TRIES -lt 30 ]; do
            RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
            EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
            if [ "$EXIT_CODE" = "0" ]; then break; fi
            TRIES=$((TRIES + 1))
            sleep 2
          done
          assert_success "systemctl is-active nftables" \
            "nftables is active"
        '';
      })
      (lib.mkCheck {
        name = "has-ssh-port";
        description = "Firewall allows SSH (port 22)";
        script = ''
          assert_output_contains "cat /etc/nftables.conf" "22" \
            "nftables.conf contains port 22"
        '';
      })
      (lib.mkCheck {
        name = "has-http-port";
        description = "Firewall allows HTTP (port 80)";
        script = ''
          assert_output_contains "cat /etc/nftables.conf" "80" \
            "nftables.conf contains port 80"
        '';
      })
      (lib.mkCheck {
        name = "has-https-port";
        description = "Firewall allows HTTPS (port 443)";
        script = ''
          assert_output_contains "cat /etc/nftables.conf" "443" \
            "nftables.conf contains port 443"
        '';
      })
      (lib.mkCheck {
        name = "default-drop";
        description = "Default policy is drop";
        script = ''
          assert_output_contains "cat /etc/nftables.conf" "policy drop" \
            "nftables default policy is drop"
        '';
      })
    ];
  }
