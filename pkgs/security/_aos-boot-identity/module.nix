##! Package-owned normal-boot identity validation and fail-closed reporting.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  packageDependencies = dependencies;
  cfg = config.aos.security.bootIdentityServices;
  initrdStage = config.aos.boot.stage == "initrd";
  units = {
    device-settle = "systemd-udev-settle.service";
    initrd-filesystems = "initrd-fs.target";
    integrity-failure = "aos-boot-integrity-failure.target";
  };
  readiness = key: units.${key};
  serviceResource = key: "${key}.service";
  command = key: {
    executable = {
      path = "${package}/bin/${key}";
      arguments = [];
    };
    ignore_failure = false;
  };
  emptyDependencies = {
    prerequisites = [];
    after = [];
    before = [];
    requires = [];
    wants = [];
    requisite = [];
    conflicts = [];
    binds_to = [];
    part_of = [];
    upholds = [];
    required_by = [];
    wanted_by = [];
    required_mounts = [];
    implicit_dependencies = false;
  };
  service = {
    key,
    description,
    dependencies,
    activationOwner ? "manager",
    failurePolicy ? null,
    logging ? false,
  }:
    {
      inherit activationOwner;
      autoStart = false;
      service = key;
      manager_identity = {
        name = key;
        aliases = [];
      };
      lifecycle = {
        inherit description;
        execution_model = "oneshot";
        environment_files = [];
        condition = [];
        pre_start = [];
        start = [(command key)];
        post_start = [];
        stop = [];
        post_stop = [];
        restart = "never";
        restart_delay_millis = 0;
        configuration_change_action = "restart";
        remain_after_exit = key != "aos-boot-identity-failure-report";
        start_timeout_millis = 90000;
        stop_timeout_millis = 90000;
      };
      inherit dependencies;
      environment = {
        variables = {};
        search_path = [package.path packageDependencies.coreutils.path packageDependencies.util-linux.path];
      };
      readiness = {
        mechanism = "successful-exit";
        signal_scope = "none";
        timeout_millis = 90000;
      };
    }
    // lib.optionalAttrs (failurePolicy != null) {failure_policy = failurePolicy;}
    // lib.optionalAttrs logging {
      logging = {
        standard_output = "structured-and-console";
        standard_error = "structured-and-console";
        namespace = null;
        directories = [];
        directory_mode = "0755";
      };
    };
  identitySuccess = service {
    activationOwner = "image";
    key = "aos-boot-identity-success";
    description = "Validate the normal boot identity";
    dependencies =
      emptyDependencies
      // {
        after = [(readiness "device-settle")];
        before = [(serviceResource "aos-boot-identity-guard")];
      };
    logging = true;
  };
  identityGuard = service {
    activationOwner = "image";
    key = "aos-boot-identity-guard";
    description = "Require a validated normal boot identity";
    dependencies =
      emptyDependencies
      // {
        after = [(serviceResource "aos-boot-identity-success")];
        before = [(readiness "initrd-filesystems")];
        wants = [(serviceResource "aos-boot-identity-success")];
        required_by = [(readiness "initrd-filesystems")];
      };
    failurePolicy = {
      handlers = [(readiness "integrity-failure")];
      dispatch = "isolate-active-goal";
    };
  };
  failureReport = service {
    key = "aos-boot-identity-failure-report";
    description = "Confirm rejected boot identity left storage closed";
    dependencies =
      emptyDependencies
      // {
        before = [(readiness "integrity-failure")];
        required_by = [(readiness "integrity-failure")];
      };
    logging = true;
  };
in {
  options.aos.security.bootIdentityServices.enable = lib.mkOption {
    type = lib.types.bool;
    default = config.aos.security.verity.enable;
    internal = true;
    description = "Whether fail-closed normal-boot identity services are active.";
  };

  config.aos.services = {
    "boot-identity.aos-boot-identity-success" = identitySuccess // {enable = initrdStage && cfg.enable;};
    "boot-identity.aos-boot-identity-guard" = identityGuard // {enable = initrdStage && cfg.enable;};
    "boot-identity.aos-boot-identity-failure-report" = failureReport // {enable = initrdStage && cfg.enable;};
  };
}
