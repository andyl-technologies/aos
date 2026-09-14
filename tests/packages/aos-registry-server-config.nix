##! Focused typed configuration checks for the AOS registry-server package.
{
  pkgs,
  lib,
}: let
  evaluate = host:
    lib.evalModules {
      inherit lib;
      modules = [
        {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.attrs;
              default = [];
            };
            "aos-registry-server".config = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
            };
          };
        }
      ];
      operatorModules = [host];
      packageModules = [
        {
          name = "aos-registry-server";
          authorization = {
            owns = ["aos-registry-server"];
            contributes = {};
          };
          configRoot = ../../pkgs/tests/_aos-registry-server-config;
          module = ../../pkgs/tests/_aos-registry-server-config/module.nix;
          outputs = {
            self = builtins.toString pkgs.aos-registry-server;
            dependencies = {};
          };
        }
      ];
    };

  configured = evaluate {
    "aos-registry-server" = {
      enable = true;
      git = {
        listenAddress = "127.0.0.1";
        port = 19418;
        exportAll = false;
      };
      cache = {
        listenAddress = "127.0.0.1";
        port = 15001;
        anonymousRead = false;
        maxConcurrentBuilds = 7;
      };
    };
  };
  disabled = evaluate {};
  invalid = evaluate {
    "aos-registry-server" = {
      enable = true;
      git.enable = false;
      cache.enable = false;
    };
  };

  rendered = configured.config."aos-registry-server".config;
  contract = assert rendered.git.REGISTRY_GIT_ENABLED == "true";
  assert rendered.git.REGISTRY_GIT_LISTEN == "127.0.0.1";
  assert rendered.git.REGISTRY_GIT_PORT == 19418;
  assert rendered.git.REGISTRY_GIT_EXPORT_ALL == "false";
  assert rendered.cache.REGISTRY_CACHE_ENABLED == "true";
  assert rendered.serve.listen == "127.0.0.1:15001";
  assert !(builtins.head rendered.serve.views).anonymous_read;
  assert (builtins.head rendered.serve.views).max_concurrent_builds == 7;
  assert disabled.config."aos-registry-server".config.git.REGISTRY_GIT_ENABLED == "false";
  assert disabled.config."aos-registry-server".config.cache.REGISTRY_CACHE_ENABLED == "false";
  assert !(builtins.all (entry: entry.assertion) invalid.config.assertions); true;
in
  pkgs.mkDerivation {
    pname = "aos-registry-server-config-check";
    version = "0";
    src = null;
    inherit contract;
    registryExpose = pkgs.aos-registry-server.expose;
    phases = [
      {
        name = "check";
        script = ''
          : "$contract"
          test -f "$registryExpose/manifest.json"
          grep -q 'aos-registry-server/git.env' "$registryExpose/manifest.json"
          grep -q 'aos-registry-server/cache.env' "$registryExpose/manifest.json"
          grep -q 'aos-registry-server/serve.toml' "$registryExpose/manifest.json"
          grep -q 'EnvironmentFile=/etc/aos/packages/aos-registry-server/git.env' \
            "$registryExpose/units/aos-registry-server-gitd.service"
          grep -q 'EnvironmentFile=/etc/aos/packages/aos-registry-server/cache.env' \
            "$registryExpose/units/aos-registry-server-cache.service"
          mkdir -p "$out"
          printf '%s\n' ok > "$out/result"
        '';
      }
    ];
  }
