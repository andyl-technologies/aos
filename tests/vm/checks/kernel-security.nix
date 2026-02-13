{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "kernel-security";
  description = "Kernel sysctl hardening checks";
  checks = [
    (mkCheck {
      name = "aslr";
      description = "ASLR is fully enabled (randomize_va_space=2)";
      script = ''
        assert_output_contains "cat /proc/sys/kernel/randomize_va_space" "2" \
          "ASLR is fully enabled"
      '';
    })
    (mkCheck {
      name = "syncookies";
      description = "TCP syncookies are enabled";
      script = ''
        assert_output_contains "cat /proc/sys/net/ipv4/tcp_syncookies" "1" \
          "TCP syncookies are enabled"
      '';
    })
    (mkCheck {
      name = "protected-hardlinks";
      description = "Protected hardlinks sysctl exists";
      script = ''
        assert_success "test -f /proc/sys/fs/protected_hardlinks" \
          "Protected hardlinks sysctl is accessible"
      '';
    })
    (mkCheck {
      name = "protected-symlinks";
      description = "Protected symlinks sysctl exists";
      script = ''
        assert_success "test -f /proc/sys/fs/protected_symlinks" \
          "Protected symlinks sysctl is accessible"
      '';
    })
    (mkCheck {
      name = "proc-isolation";
      description = "PID 1 visible in /proc";
      script = ''
        assert_success "test -d /proc/1" \
          "PID 1 visible in /proc"
      '';
    })
    (mkCheck {
      name = "syskernel";
      description = "/sys/kernel is accessible";
      script = ''
        assert_success "test -d /sys/kernel" \
          "/sys/kernel is accessible"
      '';
    })
  ];
}
