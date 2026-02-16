# tests/vm/checks/seed.nix — Seed server orchestration checks
#
# Verifies seed-specific infrastructure: build/publish services,
# timer configuration, directory structure, and nginx vhost wiring.
{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "seed";
  description = "Seed server orchestration checks";
  checks = [
    (mkCheck {
      name = "tmpfiles-config";
      description = "Seed tmpfiles config exists";
      script = ''
        assert_success "test -f /etc/tmpfiles.d/aos-seed.conf" \
          "seed tmpfiles config exists"
      '';
    })
    (mkCheck {
      name = "build-service";
      description = "aos-build-images service unit exists";
      script = ''
        assert_success "systemctl cat aos-build-images" \
          "aos-build-images service unit is loaded"
      '';
    })
    (mkCheck {
      name = "publish-service";
      description = "aos-publish-images service unit exists";
      script = ''
        assert_success "systemctl cat aos-publish-images" \
          "aos-publish-images service unit is loaded"
      '';
    })
    (mkCheck {
      name = "build-timer";
      description = "aos-build-images timer unit exists";
      script = ''
        assert_success "systemctl cat aos-build-images-timer" \
          "aos-build-images-timer unit is loaded"
      '';
    })
    (mkCheck {
      name = "nginx-vhost";
      description = "nginx config contains seed vhost";
      script = ''
        assert_output_contains "cat /etc/nginx/nginx.conf" "autoindex on" \
          "nginx config has autoindex for image serving"
      '';
    })
    (mkCheck {
      name = "nginx-basic-auth";
      description = "nginx config has basic auth for seed";
      script = ''
        assert_output_contains "cat /etc/nginx/nginx.conf" "auth_basic" \
          "nginx config has basic auth directive"
      '';
    })
    (mkCheck {
      name = "image-root-config";
      description = "nginx config serves /var/lib/aos/images";
      script = ''
        assert_output_contains "cat /etc/nginx/nginx.conf" "/var/lib/aos/images" \
          "nginx config serves image directory"
      '';
    })
  ];
}
