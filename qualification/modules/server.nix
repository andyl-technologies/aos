##! Defines the shared headless-system promises and explicit contract boundaries.
{lib, ...}: let
  types = import ./_types.nix {inherit lib;};
in {
  options.qualification = {
    id = types.text "Reviewed contract identity.";
    promises = types.strings "Functional obligations of the shared system contract.";
    exclusions = types.strings "Explicit boundaries of the contract.";
  };
  config.qualification = {
    id = "aos-system-v2";
    promises = [
      "Install authenticated public artifacts and provision a persistent headless server."
      "Configure users, SSH, DNS, time, DHCP, and single-address static networking."
      "Install, change versions, remove, and recover machine-wide package generations."
      "Activate and roll back host configuration with transaction-bound evidence."
      "Update the preceding accepted image, recover or roll back, and update again."
      "Preserve committed workload data within the declared storage and migration contract."
      "Keep update storage bounded and fail safely when resources are exhausted."
      "Run nginx HTTP/TLS and a persistent container workload on the reference targets."
    ];
    exclusions = [
      "No implicit qualification of other hardware, hypervisors, clouds, or container runtimes."
      "No SELinux enforcement claim until labeled-root and enforcing-policy gates pass."
      "No automatic reversal of application data migrations through image rollback."
      "No stock unprivileged per-user package mutation contract."
      "No uptime SLA or failure-rate inference from a finite qualification campaign."
    ];
  };
}
