# tests/vm/checks/ci-service-lifecycle.nix — Cloud-init service lifecycle
{lib}:
lib.mkCheckGroup {
  name = "ci-service-lifecycle";
  description = "Cloud-init all 4 stages complete in order";
  checks = [
    (lib.mkCheck {
      name = "boot-finished";
      description = "Boot-finished marker exists";
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
          "boot-finished marker exists"
      '';
    })
    (lib.mkCheck {
      name = "local-stage";
      description = "cloud-init-local.service completed";
      script = ''
        assert_output_contains "systemctl show -p ActiveState cloud-init-local" "active" \
          "cloud-init-local completed"
      '';
    })
    (lib.mkCheck {
      name = "network-stage";
      description = "cloud-init-network.service completed";
      script = ''
        assert_output_contains "systemctl show -p ActiveState cloud-init-network" "active" \
          "cloud-init-network completed"
      '';
    })
    (lib.mkCheck {
      name = "config-stage";
      description = "cloud-init-config.service completed";
      script = ''
        assert_output_contains "systemctl show -p ActiveState cloud-init-config" "active" \
          "cloud-init-config completed"
      '';
    })
    (lib.mkCheck {
      name = "final-stage";
      description = "cloud-init-final.service completed";
      script = ''
        assert_output_contains "systemctl show -p ActiveState cloud-init-final" "active" \
          "cloud-init-final completed"
      '';
    })
    (lib.mkCheck {
      name = "local-done-marker";
      description = "local-done state marker exists";
      script = ''
        assert_success "test -f /var/lib/cloud/state/local-done" \
          "local-done marker exists"
      '';
    })
    (lib.mkCheck {
      name = "network-done-marker";
      description = "network-done state marker exists";
      script = ''
        assert_success "test -f /var/lib/cloud/state/network-done" \
          "network-done marker exists"
      '';
    })
    (lib.mkCheck {
      name = "config-done-marker";
      description = "config-done state marker exists";
      script = ''
        assert_success "test -f /var/lib/cloud/state/config-done" \
          "config-done marker exists"
      '';
    })
  ];
}
