##! Persistent HTTP/TLS workload across reload rejection and guest reboot.
##! This is a controlled regression fixture, not a published-image attestation.
{
  pkgs,
  mkSystem,
  ...
}: let
  system = mkSystem [
    ../../systems/server-test.nix
    {
      systemd.services.qualification-nginx = {
        description = "Qualification HTTP and TLS workload";
        wantedBy = ["multi-user.target"];
        after = ["local-fs.target"];
        unitConfig.ConditionPathExists = "/var/lib/qualification/nginx.conf";
        serviceConfig = {
          Type = "simple";
          ExecStart = "${pkgs.nginx}/bin/nginx -c /var/lib/qualification/nginx.conf -g 'daemon off;'";
          ExecReload = "${pkgs.nginx}/bin/nginx -c /var/lib/qualification/nginx.conf -s reload";
          Restart = "on-failure";
        };
      };
    }
  ];
in {
  name = "qualification-workload";
  timeout = 900;
  machines.target = {
    inherit system;
    memoryMiB = 3072;
    varSizeMiB = 2048;
    extraClosures = [pkgs.nginx pkgs.openssl pkgs.curl];
  };
  testScript = ''
    import shlex
    import textwrap

    target.succeed("mkdir -p /var/lib/qualification/www")
    target.succeed("chmod 755 /var/lib/qualification /var/lib/qualification/www")
    target.succeed("${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:2048 -nodes "
                   "-keyout /var/lib/qualification/key.pem -out /var/lib/qualification/cert.pem "
                   "-days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost")
    target.succeed("chmod 600 /var/lib/qualification/key.pem")
    config = textwrap.dedent("""
        user nobody;
        worker_processes 1;
        pid /run/qualification-nginx.pid;
        error_log /var/lib/qualification/error.log;
        events { worker_connections 128; }
        http {
          access_log /var/lib/qualification/access.log;
          client_body_temp_path /var/lib/qualification/body;
          proxy_temp_path /var/lib/qualification/proxy;
          fastcgi_temp_path /var/lib/qualification/fastcgi;
          uwsgi_temp_path /var/lib/qualification/uwsgi;
          scgi_temp_path /var/lib/qualification/scgi;
          server {
            listen 8080;
            listen 8443 ssl;
            server_name localhost;
            ssl_certificate /var/lib/qualification/cert.pem;
            ssl_certificate_key /var/lib/qualification/key.pem;
            root /var/lib/qualification/www;
          }
        }
    """)
    target.succeed("printf %s " + shlex.quote(config) + " > /var/lib/qualification/nginx.conf")
    target.succeed("printf 'acknowledged-payload\\n' > /var/lib/qualification/www/state; sync")
    target.succeed("${pkgs.nginx}/bin/nginx -t -c /var/lib/qualification/nginx.conf")
    target.succeed("systemctl start qualification-nginx.service")

    def probe():
        for url in ["http://localhost:8080/state", "https://localhost:8443/state"]:
            response = target.succeed("${pkgs.curl}/bin/curl --fail --silent --show-error "
                "--cacert /var/lib/qualification/cert.pem " + url)
            assert response == "acknowledged-payload\n", response
        target.fail("${pkgs.curl}/bin/curl --fail --silent https://localhost:8443/state")

    target.wait_for_unit("qualification-nginx.service")
    probe()
    target.succeed("cp /var/lib/qualification/nginx.conf /var/lib/qualification/nginx.good")
    target.succeed("printf 'invalid;\\n' >> /var/lib/qualification/nginx.conf")
    target.fail("${pkgs.nginx}/bin/nginx -t -c /var/lib/qualification/nginx.conf")
    # Rejecting a configuration must leave the running workload available.
    probe()
    target.succeed("cp /var/lib/qualification/nginx.good /var/lib/qualification/nginx.conf")
    target.succeed("systemctl reload qualification-nginx.service")
    probe()
    target.reboot(timeout=300)
    target.wait_for_unit("qualification-nginx.service")
    probe()
    target.succeed("test $(stat -c %a /var/lib/qualification/key.pem) = 600")
  '';
}
