{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "hardening";
  description = "Userspace hardening checks";
  checks = [
    (mkCheck {
      name = "dmesg-restrict";
      description = "dmesg_restrict is enabled";
      script = ''
        assert_output_contains "cat /proc/sys/kernel/dmesg_restrict" "1" \
          "dmesg_restrict is enabled"
      '';
    })
    (mkCheck {
      name = "kptr-restrict";
      description = "kptr_restrict is set";
      script = ''
        assert_success "test -f /proc/sys/kernel/kptr_restrict" \
          "kptr_restrict sysctl exists"
      '';
    })
    (mkCheck {
      name = "ptrace-scope";
      description = "ptrace scope is restricted";
      script = ''
        assert_success "test -f /proc/sys/kernel/yama/ptrace_scope" \
          "ptrace_scope sysctl exists"
      '';
    })
  ];
}
