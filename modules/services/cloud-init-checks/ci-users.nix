# tests/vm/checks/ci-users.nix — Cloud-init user creation
{lib}:
  lib.mkCheckGroup {
    name = "ci-users";
    description = "Cloud-init user creation";
    checks = [
      (lib.mkCheck {
        name = "user-exists";
        description = "Deploy user exists in /etc/passwd";
        script = ''
          TRIES=0
          while [ $TRIES -lt 30 ]; do
            RESULT=$(run_in_guest "test -f /var/lib/cloud/state/boot-finished" 2>/dev/null || true)
            EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code' 2>/dev/null || echo "1")
            if [ "$EXIT_CODE" = "0" ]; then break; fi
            TRIES=$((TRIES + 1))
            sleep 2
          done
          assert_output_contains "cat /etc/passwd" "deploy" \
            "deploy user exists in passwd"
        '';
      })
      (lib.mkCheck {
        name = "user-uid";
        description = "Deploy user has correct UID";
        script = ''
          assert_output_contains "cat /etc/passwd" "deploy:x:1000:" \
            "deploy user has UID 1000"
        '';
      })
      (lib.mkCheck {
        name = "user-group";
        description = "Deploy user has group entry";
        script = ''
          assert_output_contains "cat /etc/group" "deploy" \
            "deploy group exists"
        '';
      })
    ];
  }
