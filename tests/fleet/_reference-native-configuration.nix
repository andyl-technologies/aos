##! Authors the native nginx reference topology used by live qualification.
{
  config,
  lib,
  ...
}: let
  effects = config.aos.abilities;
  secondaryConfiguration = effects.configuration.operations.file.effects.reference-secondary.outputs.path;
  mainService = effects.serviceManagement.operations.realize.effects.nginx.outputs.resource;
  secondaryService = effects.serviceManagement.operations.realize.effects."runtime-services.nginx-secondary".outputs.resource;
in {
  # This fixture realizes the reference service matrix before the crash test.
  # Keep its controller budget aligned with the fleet's six-hundred-second
  # boot budget, including evaluation on a busy source-build host.
  aos.services."control-plane.aos-activate".lifecycle.start_timeout_millis = lib.mkForce 600000;

  aos.services."runtime-services.nginx-main".enable = lib.mkForce false;
  aos.services.nginx = {
    enable = true;
    virtualHosts = {
      alpha = {
        serverNames = ["alpha.example"];
        listen = [18081];
        locations."/".proxyPass = "http://127.0.0.1:19001";
      };
      beta = {
        serverNames = ["beta.example"];
        listen = [18081];
        locations."/".proxyPass = "http://127.0.0.1:19002";
      };
    };
  };

  aos.services."runtime-services.nginx-secondary" = {
    activationAfter = [secondaryConfiguration];
    dependencies.prerequisites = [secondaryConfiguration];
  };
  aos.networkPolicy.ingress.reference.endpoints = [
    {
      transport = "tcp";
      port = 18081;
    }
    {
      transport = "tcp";
      port = 18082;
    }
  ];

  aos.abilities.configuration.operations.file.effects =
    (lib.genAttrs ["app-a" "app-b" "app-c"] (name: {
      after = [effects.serviceManagement.operations.realize.effects."runtime-services.setup".outputs.resource];
      input = {
        path = "/var/lib/aos/ability-reference/backends/${name}/index.html";
        content = "${name}:baseline\n";
        mode = "0444";
      };
    }))
    // {
      reference-secondary.input = {
        path = "/var/lib/aos/ability-reference/nginx-secondary.conf";
        mode = "0444";
        content = ''
          # The standalone reference daemon uses its fixture's root identity;
          # the main package daemon has a manager-owned ephemeral identity.
          user root root;
          error_log stderr;
          pid /var/lib/aos/ability-reference/nginx-secondary/nginx.pid;
          events { worker_connections 128; }
          http {
            access_log off;
            client_body_temp_path client_body;
            proxy_temp_path proxy;
            fastcgi_temp_path fastcgi;
            uwsgi_temp_path uwsgi;
            scgi_temp_path scgi;
            server {
              listen 18082;
              server_name gamma.example;
              location / { proxy_pass http://127.0.0.1:19003; }
            }
          }
        '';
      };
    };

  aos.referenceNginxConsumers = {
    main = {
      enable = true;
      service = mainService;
    };
    secondary = {
      enable = true;
      service = secondaryService;
    };
  };
  aos.referenceHttpBackend.enable = true;
  aos.referenceHttpBackend.endpoints = {
    app-a = {
      address = "127.0.0.1";
      port = 19001;
      transport = "tcp";
    };
    app-b = {
      address = "127.0.0.1";
      port = 19002;
      transport = "tcp";
    };
    app-c = {
      address = "127.0.0.1";
      port = 19003;
      transport = "tcp";
    };
  };
  aos.referenceBackendConsumers.main = {
    enable = true;
    service = mainService;
    endpoints = effects.referenceHttpBackend.operations.publish.effects.registry.outputs.endpoints;
  };
}
