##! Package-owned util-linux console getty service declarations.
##!
##! The same package module participates in host and initrd fixed points. A
##! typed stage option selects their console devices and activation milestones
##! while keeping the service contract manager-neutral.
{
  config,
  lib,
  package,
  ...
}: let
  cfg = config.aos.getty.autologin;
  isInitrd = (config.aos.boot.stage or cfg.stage) == "initrd";
  command = arguments: {
    executable = {
      path = "${package}/libexec/aos-autologin-getty";
      inherit arguments;
    };
    ignore_failure = false;
  };
  startupReadiness =
    if isInitrd
    then "sysinit.target"
    else "getty.target";
  userSessionsReadiness = "systemd-user-sessions.service";

  consoleService = {
    service,
    description,
    terminal,
    arguments,
    deallocate,
    sessionIdentifier ? null,
  }: {
    activationOwner =
      if isInitrd
      then "image"
      else "ability";
    autoStart = !isInitrd;
    manager_identity =
      if isInitrd
      then {
        name = "debug-shell-${service}";
        aliases = [];
      }
      else null;
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
      # Interactive initrd shells ignore TERM; keep switch-root's kill wait short.
      stop_timeout_millis =
        if isInitrd
        then 5000
        else 90000;
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
    service = "console";
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
    service = "serial";
    description =
      if isInitrd
      then "Initrd debug shell on ttyS0"
      else "Autologin serial getty on ttyS0";
    terminal = "ttyS0";
    arguments = ["-s" "ttyS0" "115200" "vt100"];
    deallocate = false;
  };
in {
  options.aos.getty.autologin = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Run passwordless root gettys on the primary virtual and serial consoles.";
    };
    stage = lib.mkOption {
      type = lib.types.enum ["host" "initrd"];
      default = "host";
      description = "Select the host or initrd console and activation contract.";
    };
  };

  config.aos.services = {
    "getty.virtual-console" = virtualConsole // {enable = cfg.enable;};
    "getty.serial-console" = serialConsole // {enable = cfg.enable;};
  };
}
