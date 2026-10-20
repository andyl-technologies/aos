# Authored operator source shared by the runtime acceptance machines.
{
  pkgs,
  hostname,
  value,
  filePath ? "runtime-config/runtime.conf",
  fileContent ? "generation=${value}\n",
  account ? false,
  service ? false,
  certificate ? null,
}: ''
  { config, ... }: {
    aos.networking.hostName = ${builtins.toJSON hostname};
    aos.abilities.configuration.operations.file.effects = {
      runtime-hostname.input = {
        path = "/etc/hostname";
        content = ${builtins.toJSON (hostname + "\n")};
        mode = "0644";
      };
      runtime-config.input = {
        path = ${builtins.toJSON ("/etc/" + filePath)};
        content = ${builtins.toJSON fileContent};
        mode = "0644";
      };
      ${
    if certificate == null
    then ""
    else
      builtins.concatStringsSep "\n" (map (path: ''
        ca-${builtins.hashString "sha256" path}.input = {
          path = ${builtins.toJSON path};
          fragments = [
            { credentialPath = "${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt"; maximumBytes = 1048576; }
            ${builtins.toJSON certificate}
          ];
          mode = "0444";
        };
      '') ["/etc/ssl/certs/ca-certificates.crt" "/etc/ssl/certs/ca-bundle.crt" "/etc/pki/tls/certs/ca-bundle.crt"])
  }
    };
    ${
    if !account
    then ""
    else ''
      aos.abilities.identity.operations.group.effects.runtime-config.input = {
        name = "runtime-config";
        requested_id = 976;
      };
      aos.abilities.identity.operations.principal.effects.runtime-config.input = {
        name = "runtime-config";
        requested_id = 976;
        primary_group = config.aos.abilities.identity.operations.group.effects.runtime-config.outputs.name;
        home_directory = "/var/lib/runtime-config";
        description = "Runtime-configured host user";
      };
    ''
  }
    ${
    if !service
    then ""
    else ''
      aos.services.runtime-config-host = {
        enable = true;
        lifecycle = {
          description = "Runtime-configured host service";
          execution_model = "oneshot";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [{
            executable = {
              path = "${pkgs.bash}/bin/bash";
              arguments = [ "-c" "printf ${value} > /run/runtime-config-host-service" ];
            };
            ignore_failure = false;
          }];
          post_start = [];
          stop = [];
          post_stop = [];
          restart = "never";
          restart_delay_millis = 0;
          configuration_change_action = "restart";
          remain_after_exit = true;
          start_timeout_millis = 30000;
          stop_timeout_millis = 30000;
        };
      };
    ''
  }
  }
''
