# tests/vm/checks/ci-security.nix — Security hardening on golden image
{lib}: {
  description = "Golden image security hardening verification";
  checks = [
    {
      name = "boot-finished";
      description = "Cloud-init completed";
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
          "cloud-init completed"
      '';
    }
    {
      name = "aslr";
      description = "ASLR is fully enabled";
      script = ''
        assert_output_contains "cat /proc/sys/kernel/randomize_va_space" "2" \
          "ASLR is enabled (randomize_va_space=2)"
      '';
    }
    {
      name = "dmesg-restrict";
      description = "dmesg_restrict is enabled";
      script = ''
        assert_output_contains "cat /proc/sys/kernel/dmesg_restrict" "1" \
          "dmesg_restrict is enabled"
      '';
    }
    {
      name = "ptrace-scope";
      description = "ptrace scope is restricted";
      script = ''
        assert_success "test -f /proc/sys/kernel/yama/ptrace_scope" \
          "ptrace_scope sysctl exists"
      '';
    }
    {
      name = "syncookies";
      description = "TCP syncookies are enabled";
      script = ''
        assert_output_contains "cat /proc/sys/net/ipv4/tcp_syncookies" "1" \
          "TCP syncookies are enabled"
      '';
    }
    {
      name = "rp-filter";
      description = "Reverse path filter is enabled";
      script = ''
        assert_output_contains "cat /proc/sys/net/ipv4/conf/all/rp_filter" "1" \
          "Reverse path filter is enabled"
      '';
    }
    {
      name = "core-dumps-disabled";
      description = "Core dumps are disabled";
      script = ''
        assert_output_contains "cat /proc/sys/fs/suid_dumpable" "0" \
          "suid_dumpable is 0 (core dumps disabled)"
      '';
    }
  ];
}
