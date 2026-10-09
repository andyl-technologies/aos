##! Installs the manager bootstrap that activates deferred container effects.
{
  config,
  lib,
  ...
}: let
  target = config.aos.initSystem;
  executable = target.containerStartupExecutable;
  enabled = target.container && executable != null;
  quote = value: ''"${builtins.replaceStrings ["\\" "\"" "%"] ["\\\\" "\\\"" "%%"] value}"'';
  arguments = [
    "container-startup"
    "--activate"
    "--image-input"
    "/usr/lib/aos-container/native-deployment"
    "--state-directory"
    "/var/lib/apm/container-runtime"
  ];
  unit = ''
    [Unit]
    Description=Activate installed container effects
    Requires=dbus.service
    After=basic.target dbus.service

    [Service]
    Type=oneshot
    Environment=AOS_RUNTIME=container
    # Preserve the caller's Nix policy when activation launches Nix children.
    PassEnvironment=NIX_CONFIG
    ExecStart=${builtins.concatStringsSep " " (builtins.map quote ([executable] ++ arguments))}
    RemainAfterExit=yes
    TimeoutStartSec=300
  '';
in {
  # The startup effect graph cannot install the unit that invokes that same
  # graph. Prepare this bootstrap topology before launching the manager.
  aos.abilities.configuration.operations.file.effects = lib.mkIf enabled {
    systemd-container-startup.input = {
      path = "/etc/systemd/system/aos-container-startup.service";
      content = unit;
      mode = "0444";
    };
    systemd-container-startup-target.input = {
      path = "/etc/systemd/system/multi-user.target.d/90-aos-runtime.conf";
      content = ''
        [Unit]
        Wants=aos-container-startup.service
      '';
      mode = "0444";
    };
  };
}
