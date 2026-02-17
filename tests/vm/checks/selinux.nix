{
  mkCheck,
  mkCheckGroup,
}:
mkCheckGroup {
  name = "selinux";
  description = "SELinux checks";
  checks = [
    (mkCheck {
      name = "selinuxfs";
      description = "/sys/fs/selinux is present";
      script = ''
        assert_success "test -d /sys/fs/selinux" \
          "/sys/fs/selinux is present"
      '';
    })
    (mkCheck {
      name = "enforce-file";
      description = "SELinux enforce file exists";
      script = ''
        assert_success "test -f /sys/fs/selinux/enforce" \
          "SELinux enforce file exists"
      '';
    })
  ];
}
