{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "chrony";
  description = "NTP time sync checks";
  checks = [
    (mkCheck {
      name = "chronyd-active";
      description = "chronyd service is active";
      script = ''
        # chronyd may take a few seconds to finish forking (DNS resolution, etc.)
        TRIES=0
        while [ $TRIES -lt 15 ]; do
          RESULT=$(run_in_guest "systemctl is-active chronyd" 2>/dev/null || true)
          STATUS=$(echo "$RESULT" | jq -r '.stdout // empty' 2>/dev/null || echo "$RESULT")
          if [ "$STATUS" = "active" ]; then
            break
          fi
          TRIES=$((TRIES + 1))
          sleep 2
        done
        if [ "$STATUS" != "active" ]; then
          echo "chronyd status after retries: $STATUS"
          echo "--- systemctl status chronyd ---"
          run_in_guest "systemctl status chronyd 2>&1 || true" || true
          echo "--- journalctl -u chronyd ---"
          run_in_guest "journalctl -u chronyd --no-pager 2>&1 || true" || true
        fi
        assert_success "systemctl is-active chronyd" \
          "chronyd service is active"
      '';
    })
    (mkCheck {
      name = "chrony-config";
      description = "chrony.conf exists";
      script = ''
        assert_success "test -f /etc/chrony.conf" \
          "chrony.conf exists"
      '';
    })
  ];
}
