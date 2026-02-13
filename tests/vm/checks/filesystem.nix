{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "filesystem";
  description = "Filesystem layout checks";
  checks = [
    (mkCheck {
      name = "tmp-tmpfs";
      description = "/tmp is tmpfs";
      script = ''
        assert_output_contains "cat /proc/mounts" "/tmp tmpfs" \
          "/tmp is tmpfs"
      '';
    })
    (mkCheck {
      name = "run-tmpfs";
      description = "/run is tmpfs";
      script = ''
        assert_output_contains "cat /proc/mounts" "/run tmpfs" \
          "/run is tmpfs"
      '';
    })
    (mkCheck {
      name = "nix-store-exists";
      description = "/nix/store directory exists";
      script = ''
        assert_success "test -d /nix/store" \
          "/nix/store directory exists"
      '';
    })
    (mkCheck {
      name = "nix-store-populated";
      description = "/nix/store is populated";
      script = ''
        assert_success "ls /nix/store/ | head -1" \
          "/nix/store is populated"
      '';
    })
    (mkCheck {
      name = "var-writable";
      description = "/var is writable";
      script = ''
        assert_success "touch /var/test-write && rm /var/test-write" \
          "/var is writable"
      '';
    })
    (mkCheck {
      name = "etc-os-release";
      description = "/etc/os-release exists";
      script = ''
        assert_success "test -f /etc/os-release" \
          "/etc/os-release exists"
      '';
    })
    (mkCheck {
      name = "etc-passwd";
      description = "/etc/passwd exists";
      script = ''
        assert_success "test -f /etc/passwd" \
          "/etc/passwd exists"
      '';
    })
  ];
}
