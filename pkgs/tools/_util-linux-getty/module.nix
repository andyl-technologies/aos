##! Package-owned util-linux console getty service declarations.
##!
##! The same package module participates in host and initrd fixed points. A
##! typed stage option selects their console devices and activation milestones
##! while keeping the service contract manager-neutral.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.services.getty.autologin;
  isInitrd = cfg.stage == "initrd";
  anyConsoleEnabled =
    config.aos.services."getty.virtual-console".enable
    || config.aos.services."getty.serial-console".enable;
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  resultOf = lib.abilities.resultOf;
  consumerInstance = "getty";

  command = arguments: {
    executable = {
      artifact = lib.abilities.packageOutput {};
      entry_point = "libexec/aos-autologin-getty";
      inherit arguments;
    };
    ignore_failure = false;
  };
  milestone = key: name:
    serviceManagement.forProducer {
      inherit consumerInstance key;
      interface = interfaces.activationMilestone;
      parameters.milestone = name;
    };
  startupMilestone = milestone "startup-milestone" (
    if isInitrd
    then "early-system"
    else "interactive-console"
  );
  userSessionsMilestone = milestone "user-sessions-milestone" "user-sessions-ready";
  startupReadiness = resultOf "startup-milestone" "resource";
  userSessionsReadiness = resultOf "user-sessions-milestone" "resource";

  consoleService = {
    service,
    description,
    terminal,
    arguments,
    deallocate,
    sessionIdentifier ? null,
  }: {
    inherit consumerInstance service;
    lifecycle = {
      inherit description;
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [(command arguments)];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "always";
      restart_delay_millis = 0;
      configuration_change_action = "restart";
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = lib.optional (!isInitrd) userSessionsReadiness;
      before = [];
      requires = [];
      wants = [];
      wanted_by = [startupReadiness];
      implicit_dependencies = !isInitrd;
    };
    readiness = {
      mechanism = "process-running";
      signal_scope = "none";
      timeout_millis = 90000;
    };
    terminal =
      {
        device = "/dev/${terminal}";
        reset = true;
        hangup = true;
        inherit deallocate;
        send_hangup_on_stop = !isInitrd;
        start_when_idle = !isInitrd;
      }
      // lib.optionalAttrs (sessionIdentifier != null) {
        session_identifier = sessionIdentifier;
      };
  };

  virtualConsole = consoleService {
    service = "virtual-console";
    description =
      if isInitrd
      then "Initrd debug shell on tty0"
      else "Autologin getty on tty1";
    terminal =
      if isInitrd
      then "tty0"
      else "tty1";
    arguments = [
      "--noclear"
      (
        if isInitrd
        then "tty0"
        else "tty1"
      )
      "linux"
    ];
    deallocate = !isInitrd;
    sessionIdentifier =
      if isInitrd
      then null
      else "tty1";
  };
  serialConsole = consoleService {
    service = "serial-console";
    description =
      if isInitrd
      then "Initrd debug shell on ttyS0"
      else "Autologin serial getty on ttyS0";
    terminal = "ttyS0";
    arguments = ["-s" "ttyS0" "115200" "vt100"];
    deallocate = false;
  };
in {
  options.aos.services = lib.mkOption {
    type = lib.types.lazyAttrsOf (lib.types.submodule ({name, ...}: {
      options = lib.optionalAttrs (name == "getty") {
        autologin = {
          enable = lib.mkOption {
            type = lib.abilities.types.boolean;
            default = false;
            description = "Run passwordless root gettys on the primary virtual and serial consoles.";
          };

          stage = lib.mkOption {
            type = lib.abilities.types.enum ["host" "initrd"];
            default = "host";
            description = "Select the host or initrd console and activation contract.";
          };
        };
      };
    }));
    default = {};
  };

  config = lib.mkMerge [
    {
      aos.services = {
        getty = {};
        "getty.virtual-console" = virtualConsole // {enable = cfg.enable;};
        "getty.serial-console" = serialConsole // {enable = cfg.enable;};
      };
    }
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [startupMilestone];
      enabled = anyConsoleEnabled;
    })
    (serviceManagement.producerModule {
      inherit config lib;
      producers = [userSessionsMilestone];
      enabled = anyConsoleEnabled && !isInitrd;
    })
  ];
}
