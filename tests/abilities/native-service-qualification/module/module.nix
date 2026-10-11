##! Authors controlled service and account resources for native fleet flights.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.nativeServiceQualification;
  afterFor = name: lib.optional (cfg.dependencyParents.${name} != null) cfg.dependencyParents.${name};
  identity = config.aos.abilities.identity.operations;
  command = name: {
    executable = {
      path = "${package}/bin/native-service-qualification";
      arguments = [name];
    };
    ignore_failure = false;
  };
  service = name: autoStart: {
    inherit autoStart;
    enable = true;
    activationAfter = [config.aos.abilities.filesystem.operations.directory.effects.native-service-qualification.outputs.path];
    lifecycle = {
      description = "Native fleet ${name} process";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      post_start = [];
      stop = [];
      post_stop = [];
      restart_delay_millis = 1000;
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
      start = [(command name)];
      restart = "never";
    };
  };
in {
  options.aos.nativeServiceQualification = {
    enabled = lib.mkOption {
      type = lib.types.submodule {
        options = lib.genAttrs ["service" "group" "principal" "membership" "deadline" "deadlineRemove"] (_:
          lib.mkOption {
            type = lib.types.bool;
            default = true;
          });
      };
      default = {};
      description = "Controlled native service and identity resources.";
    };
    dependencyParents = lib.mkOption {
      type = lib.types.submodule {
        options = lib.genAttrs ["service" "group" "principal" "membership"] (_: lib.mkOption {
          type = lib.types.nullOr lib.types.effectOutput;
          default = null;
        });
      };
      default = {};
      description = "Authored native marker prerequisites for the selected fixture operations.";
    };
    autoStart = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Start the controlled process through actual native activation.";
    };
    groupId = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = 61501;
      description = "Numeric identity requested for the controlled group.";
    };
    principalDescription = lib.mkOption {
      type = lib.types.str;
      default = "Native fleet baseline principal";
      description = "Controlled account database description.";
    };
    grantMembership = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Grant the selected member while retaining the foreign member.";
    };
  };

  config = {
    aos.abilities.filesystem.operations.directory.effects.native-service-qualification.input = {
      path = "/var/lib/aos/native-service-qualification";
      mode = "0750";
    };
    aos.services = {
      native-service-qualification = lib.recursiveUpdate (service "selected" cfg.autoStart) {
        enable = cfg.enabled.service;
        activationAfter = [config.aos.abilities.filesystem.operations.directory.effects.native-service-qualification.outputs.path] ++ afterFor "service";
      };
      native-service-foreign = service "foreign" true;
      # Unit command waits are deliberately unbounded in these disposable
      # fixtures. The native invocation's admitted timeout owns the deadline.
      native-service-deadline = lib.recursiveUpdate (service "deadline" true) {
        enable = cfg.enabled.deadline;
        lifecycle = {
          execution_model = "oneshot";
          start_timeout_unbounded = true;
        };
      };
      native-service-deadline-remove = lib.recursiveUpdate (service "deadline-remove" true) {
        enable = cfg.enabled.deadlineRemove;
        lifecycle = {
          stop = [(command "deadline-stop")];
          stop_timeout_unbounded = true;
        };
      };
    };
    aos.abilities.identity.operations = {
      group.effects = {
        native-service-qualification = lib.mkIf cfg.enabled.group {
          after = afterFor "group";
          input = {
            name = "aos-nq-selected";
            requested_id = cfg.groupId;
          };
        };
        native-service-members.input = {
          name = "aos-nq-members";
          requested_id = 61502;
        };
        native-service-foreign.input = {
          name = "aos-nq-foreign";
          requested_id = 61503;
        };
      };
      principal.effects = {
        native-service-qualification = lib.mkIf cfg.enabled.principal {
          after = afterFor "principal";
          input = {
            name = "aos-nq-selected";
            requested_id = 61501;
            primary_group = identity.group.effects.native-service-foreign.outputs.name;
            description = cfg.principalDescription;
          };
        };
        native-service-member.input = {
          name = "aos-nq-member";
          requested_id = 61502;
          primary_group = identity.group.effects.native-service-foreign.outputs.name;
        };
        native-service-foreign.input = {
          name = "aos-nq-foreign";
          requested_id = 61503;
          primary_group = identity.group.effects.native-service-foreign.outputs.name;
        };
      };
      membership.effects = {
        native-service-qualification = lib.mkIf cfg.enabled.membership {
          after = afterFor "membership";
          input = {
            group = identity.group.effects.native-service-members.outputs.name;
            members = lib.optional cfg.grantMembership identity.principal.effects.native-service-member.outputs.name;
          };
        };
        native-service-foreign.input = {
          group = identity.group.effects.native-service-members.outputs.name;
          members = [identity.principal.effects.native-service-foreign.outputs.name];
        };
      };
    };
  };
}
