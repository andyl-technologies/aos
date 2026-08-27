##! Focused evaluation checks for the nginx package configuration interface.
##!
##! Exercises a representative reverse-proxy plus health endpoint, proves the
##! rendered nginx configuration is package-owned, and checks that the scoped
##! artifact authorization cannot be reused to write a neighboring `/etc`
##! path.
{
  pkgs,
  lib,
  mkSystem,
  serverModule,
}: let
  artifactAuthorization = {
    owns = ["nginx"];
    contributes = {};
    artifacts = {
      etc = ["nginx/nginx.conf"];
      units = [];
      users = [];
      groups = [];
    };
  };
  projectionStub = {
    options.nginx.config = lib.mkOption {
      type = lib.types.attrs;
      default = {};
      internal = true;
    };
  };
  evaluated = mkSystem {
    modules = [serverModule projectionStub];
    packageModules = [
      {
        name = "nginx";
        authorization = artifactAuthorization;
        configRoot = ../../pkgs/networking/_nginx-config;
        module = ../../pkgs/networking/_nginx-config/module.nix;
        outputs = {
          self = builtins.toString pkgs.nginx;
          dependencies = {};
        };
      }
      {
        name = "nginx-site-profile";
        authorization = {
          owns = [];
          contributes = {nginx = ["virtualHosts"];};
        };
        module = {
          nginx.virtualHosts.meta-package = {
            listen = [8081];
            serverNames = ["profile.example.test"];
            locations."/ready"."return" = {
              code = 200;
              body = "profile-ready\n";
            };
          };
        };
      }
    ];
    runtimeModules = [
      {
        nginx = {
          enable = true;
          workerProcesses = 2;
          upstreams.application = {
            servers = [
              {
                address = "127.0.0.1:3000";
                weight = 2;
              }
            ];
            keepalive = 16;
          };
          virtualHosts.default = {
            listen = [8080];
            serverNames = ["example.test"];
            locations = {
              "/".proxyPass = "http://application";
              "/health"."return" = {
                code = 200;
                body = "healthy\n";
              };
            };
          };
        };
      }
    ];
  };
  manifest = evaluated.config.system.build.configManifest;
  rendered = manifest.etc."nginx/nginx.conf".text;
  renderedFile = pkgs.writeTextFile {
    name = "nginx-config-module-check";
    destination = "/nginx.conf";
    text = rendered;
  };
  unauthorized = builtins.tryEval (builtins.toJSON ((mkSystem {
      modules = [serverModule];
      packageModules = [
        {
          name = "nginx";
          authorization = artifactAuthorization;
          module.environment.etc."nginx-neighbor.conf".text = "forbidden\n";
        }
      ];
    })
    .config
    .system
    .build
    .configManifest
    .etc));
  contract = assert manifest.ownership.etc."nginx/nginx.conf" == "nginx";
  assert lib.hasInfix "worker_processes 2;" rendered;
  assert lib.hasInfix "upstream application" rendered;
  assert lib.hasInfix "server 127.0.0.1:3000 weight=2;" rendered;
  assert lib.hasInfix "listen 8080;" rendered;
  assert lib.hasInfix "proxy_pass http://application;" rendered;
  assert lib.hasInfix ''return 200 "healthy\n";'' rendered;
  assert lib.hasInfix "listen 8081;" rendered;
  assert lib.hasInfix "profile.example.test" rendered;
  assert lib.hasInfix ''return 200 "profile-ready\n";'' rendered;
  assert evaluated.config.nginx.config.runtime.enabled;
  assert builtins.stringLength evaluated.config.nginx.config.runtime.generation == 64;
  assert !unauthorized.success; true;
in
  assert contract;
    pkgs.mkDerivation {
      pname = "nginx-config-module-check";
      version = "0";
      src = null;
      nginxExpose = pkgs.nginx.expose;
      phases = [
        {
          name = "check";
          script = ''
            test -f "$nginxExpose/manifest.json"
            grep -q '"encrypted":false,"name":"tls-certificate","optional":true,"source":"/run/credstore/nginx/tls-certificate","units":\["nginx.service"\]' \
              "$nginxExpose/manifest.json"
            grep -q '"encrypted":false,"name":"tls-private-key","optional":true,"source":"/run/credstore/nginx/tls-private-key","units":\["nginx.service"\]' \
              "$nginxExpose/manifest.json"
            if grep -Eq 'LoadCredential(Encrypted)?=tls-' "$nginxExpose/units/nginx.service"; then
              echo "optional nginx TLS credentials must not become unconditional static unit bindings" >&2
              exit 1
            fi

            mkdir -p "$TMPDIR/state"
            sed \
              -e "s#pid /run/nginx/nginx.pid;#pid $TMPDIR/nginx.pid;#" \
              -e "s#/var/lib/aos-pkg-nginx#$TMPDIR/state#g" \
              ${renderedFile}/nginx.conf > "$TMPDIR/nginx.conf"
            ${pkgs.nginx}/bin/nginx -t -c "$TMPDIR/nginx.conf"
            mkdir -p "$out"
            printf '%s\n' PASS > "$out/result"
          '';
        }
      ];
    }
