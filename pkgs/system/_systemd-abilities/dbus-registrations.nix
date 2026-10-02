##! Registers systemd's own system-bus policy and activation definitions.
{
  lib,
  options,
  package,
  ...
}: {
  # Independent initrd scopes need not admit a system-bus consumer.
  config.aos = lib.optionalAttrs ((options.aos.dbus or {}) ? policyDirectories && (options.aos.dbus or {}) ? activationDirectories) {
    dbus = {
      policyDirectories = ["${package}/share/dbus-1/system.d"];
      activationDirectories = ["${package}/share/dbus-1/system-services"];
    };
  };
}
