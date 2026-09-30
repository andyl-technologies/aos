##! Checks that the real systemd module selects the native rich service handler.
{lib, pkgs}: let
  evaluated = lib.evalPackageModules {
    scope = ["test" "native-systemd-services"];
    packages = [pkgs.systemd];
    operatorModules = [{
      aos.services.example = {
        enable = true;
        activationOwner = "image";
        autoStart = false;
        manager_identity = {name = "example"; aliases = ["example-alias"];};
        lifecycle = {
          description = "Native systemd service realization fixture";
          execution_model = "oneshot";
          environment_files = [];
          condition = [];
          pre_start = [];
          start = [{executable = {path = "${pkgs.coreutils}/bin/true"; arguments = [];}; ignore_failure = false;}];
          post_start = [];
          stop = [];
          post_stop = [];
          restart = "never";
          restart_delay_millis = 0;
          remain_after_exit = true;
          start_timeout_millis = 90000;
          stop_timeout_millis = 90000;
        };
        directories.managed = [{path = "example/nested"; purpose = "state"; mode = "0750"; retention = "persistent"; owner = "example"; group = "example";}];
        conditions.all = [{kind = "path"; predicate = "exists"; path = "/run/example"; negated = false;}];
      };
    }];
  };
  services = builtins.filter (node: builtins.elem "serviceManagement" node.identity)
    (builtins.attrValues evaluated.deployment.graph.nodes);
  example = builtins.head (builtins.filter (node: builtins.elem "example" node.identity) services);
in
  assert example.owner == "service-management";
  assert example.handler.executable == "${pkgs.systemd}/bin/aos-service-handler";
  assert example.input.activation_owner == "image";
  assert !example.input.auto_start;
  assert (builtins.head example.input.directories.managed).owner == "example";
  assert (builtins.head example.input.conditions.all).predicate == "exists";
  assert example.input.manager_identity.aliases == ["example-alias"]; true
