{
  mkCheck,
  mkCheckGroup,
}:
mkCheckGroup {
  name = "container-support";
  description = "Container kernel feature checks";
  checks = [
    (mkCheck {
      name = "cgroups-v2";
      description = "cgroups v2 filesystem is mounted";
      script = ''
        assert_success "test -d /sys/fs/cgroup" \
          "cgroups filesystem is mounted"
      '';
    })
    (mkCheck {
      name = "pid-namespace";
      description = "PID namespaces available";
      script = ''
        assert_success "test -f /proc/self/ns/pid" \
          "PID namespaces available"
      '';
    })
    (mkCheck {
      name = "net-namespace";
      description = "Network namespaces available";
      script = ''
        assert_success "test -f /proc/self/ns/net" \
          "Network namespaces available"
      '';
    })
    (mkCheck {
      name = "mnt-namespace";
      description = "Mount namespaces available";
      script = ''
        assert_success "test -f /proc/self/ns/mnt" \
          "Mount namespaces available"
      '';
    })
  ];
}
