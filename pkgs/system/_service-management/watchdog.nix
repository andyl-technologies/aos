##! Defines manager watchdog configuration and typed lifecycle results.
{lib, ...}: let
  timeout = description:
    lib.mkOption {
      type = lib.types.ints.between 0 172800000;
      inherit description;
    };
in {
  aos.abilities.managerWatchdog.operations.ensure = {
    input.options = {
      enabled = lib.mkOption {
        type = lib.types.bool;
        description = "Enable manager hardware watchdog timeouts.";
      };
      runtime_timeout_millis = timeout "Runtime watchdog timeout in milliseconds.";
      reboot_timeout_millis = timeout "Reboot watchdog timeout in milliseconds.";
      kexec_timeout_millis = timeout "Kexec watchdog timeout in milliseconds.";
    };
    result.options.resource = lib.mkOption {
      type = lib.types.str;
      description = "Owned manager watchdog configuration path.";
    };
  };
}
