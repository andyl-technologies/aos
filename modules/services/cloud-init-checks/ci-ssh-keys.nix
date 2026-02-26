# tests/vm/checks/ci-ssh-keys.nix — Cloud-init SSH authorized keys
{lib}:
  lib.mkCheckGroup {
    name = "ci-ssh-keys";
    description = "Cloud-init SSH key provisioning";
    checks = [
      (lib.mkCheck {
        name = "authorized-keys-file";
        description = "Authorized keys file exists for deploy user";
        script = ''
          TRIES=0
          while [ $TRIES -lt 30 ]; do
            RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
            EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
            if [ "$EXIT_CODE" = "0" ]; then break; fi
            TRIES=$((TRIES + 1))
            sleep 2
          done
          assert_success "test -f /etc/ssh/authorized_keys/deploy" \
            "authorized_keys file exists for deploy"
        '';
      })
      (lib.mkCheck {
        name = "key-content";
        description = "Authorized keys file contains the SSH key";
        script = ''
          assert_output_contains "cat /etc/ssh/authorized_keys/deploy" "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" \
            "authorized_keys contains ed25519 key"
        '';
      })
    ];
  }
