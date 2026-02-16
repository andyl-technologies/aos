# tests/vm/checks/nix-daemon.nix — Nix daemon checks
#
# Verifies the Nix daemon configuration, service unit, build users,
# and state directories.
{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "nix-daemon";
  description = "Nix package manager daemon checks";
  checks = [
    (mkCheck {
      name = "nix-conf-exists";
      description = "nix.conf is generated";
      script = ''
        assert_success "test -f /etc/nix/nix.conf" \
          "/etc/nix/nix.conf exists"
      '';
    })
    (mkCheck {
      name = "nix-conf-sandbox";
      description = "nix.conf enables sandboxing";
      script = ''
        assert_output_contains "cat /etc/nix/nix.conf" "sandbox = true" \
          "nix.conf has sandbox = true"
      '';
    })
    (mkCheck {
      name = "nix-conf-flakes";
      description = "nix.conf enables flakes";
      script = ''
        assert_output_contains "cat /etc/nix/nix.conf" "nix-command flakes" \
          "nix.conf enables flakes experimental feature"
      '';
    })
    (mkCheck {
      name = "service-loaded";
      description = "nix-daemon systemd service unit exists";
      script = ''
        assert_success "systemctl cat nix-daemon" \
          "nix-daemon service unit is loaded"
      '';
    })
    (mkCheck {
      name = "build-user-exists";
      description = "nixbld1 build user exists";
      script = ''
        assert_output_contains "cat /etc/passwd" "nixbld1" \
          "nixbld1 user exists in /etc/passwd"
      '';
    })
    (mkCheck {
      name = "build-group-exists";
      description = "nixbld group exists";
      script = ''
        assert_output_contains "cat /etc/group" "nixbld" \
          "nixbld group exists in /etc/group"
      '';
    })
    (mkCheck {
      name = "tmpfiles-config";
      description = "Nix tmpfiles config exists";
      script = ''
        assert_success "test -f /etc/tmpfiles.d/aos-nix.conf" \
          "Nix tmpfiles config exists"
      '';
    })
  ];
}
