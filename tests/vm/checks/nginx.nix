# tests/vm/checks/nginx.nix — nginx web server checks
#
# Verifies nginx configuration, service unit, and binary presence.
# ACME certificate issuance is not tested (requires internet + real domain);
# these checks validate that the nginx infrastructure is correctly wired.
{ mkCheck, mkCheckGroup }:
mkCheckGroup {
  name = "nginx";
  description = "nginx web server checks";
  checks = [
    (mkCheck {
      name = "config-exists";
      description = "nginx.conf is generated";
      script = ''
        assert_success "test -f /etc/nginx/nginx.conf" \
          "nginx.conf exists"
      '';
    })
    (mkCheck {
      name = "config-worker-processes";
      description = "nginx.conf has worker_processes directive";
      script = ''
        assert_output_contains "cat /etc/nginx/nginx.conf" "worker_processes" \
          "nginx.conf contains worker_processes"
      '';
    })
    (mkCheck {
      name = "config-listen-80";
      description = "nginx.conf listens on port 80";
      script = ''
        assert_output_contains "cat /etc/nginx/nginx.conf" "listen 80" \
          "nginx.conf contains listen 80"
      '';
    })
    (mkCheck {
      name = "config-listen-443";
      description = "nginx.conf has HTTPS server block";
      script = ''
        assert_output_contains "cat /etc/nginx/nginx.conf" "listen 443 ssl" \
          "nginx.conf contains listen 443 ssl"
      '';
    })
    (mkCheck {
      name = "config-acme";
      description = "nginx.conf loads ACME module";
      script = ''
        assert_output_contains "cat /etc/nginx/nginx.conf" "ngx_http_acme_module" \
          "nginx.conf loads ACME module"
      '';
    })
    (mkCheck {
      name = "service-loaded";
      description = "nginx systemd service unit exists";
      script = ''
        assert_success "systemctl cat nginx" \
          "nginx service unit is loaded"
      '';
    })
    (mkCheck {
      name = "tmpfiles-config";
      description = "nginx tmpfiles config exists";
      script = ''
        assert_success "test -f /etc/tmpfiles.d/aos-nginx.conf" \
          "nginx tmpfiles config exists"
      '';
    })
    (mkCheck {
      name = "firewall-http";
      description = "Firewall allows port 80";
      script = ''
        assert_output_contains "cat /etc/nftables.conf" "80" \
          "nftables config includes port 80"
      '';
    })
    (mkCheck {
      name = "firewall-https";
      description = "Firewall allows port 443";
      script = ''
        assert_output_contains "cat /etc/nftables.conf" "443" \
          "nftables config includes port 443"
      '';
    })
  ];
}
