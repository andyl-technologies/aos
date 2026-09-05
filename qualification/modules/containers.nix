##! Defines native container scopes, functional checks and observation policy.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification.containers;
  types = import ./_types.nix {inherit lib;};
  target = platform: {
    inherit platform;
    kind = "container";
    required = true;
    environment = {
      layers = [
        {
          inherit platform;
          backend = {
            kind = "physical";
            physical = {};
          };
        }
        {
          inherit platform;
          backend = {
            kind = "container";
            container.runtime = "containerd-runc";
          };
        }
      ];
      boot = "linux-container";
      resources.cpus = 1;
    };
  };
in {
  options.qualification.containers.lifecycleCycles = (types.option types.positive "Minimum stop/start/recreate cycles.") // {default = 10;};
  config.qualification = {
    targets = {
      container-x86_64-linux = target "x86_64-linux";
      container-aarch64-linux = target "aarch64-linux";
    };
    requirements = {
      container-lifecycle = {
        phase = "staging";
        scope = "containers";
        checks = [
          "signed-index-and-platform-selection"
          "anonymous-pull"
          "native-platform-execution"
          "start-stop-network"
          "repeated-stop-start-and-recreate"
          "persistent-state"
          "resource-limits-and-signals"
          "declared-privileges-only"
          "runtime-identity"
          "testing-or-production-profile"
        ];
        measurements.lifecycle_cycles.minimum = cfg.lifecycleCycles;
        regressions = ["checks.container.all" "checks.fleet.container-runtime" "checks.fleet.hub-oci"];
      };
      container-observation = {
        phase = "complete";
        scope = "containers";
        checks = ["mixed-workload-soak" "operation-denominators" "committed-data-preserved"];
        measurements = {
          workload_operations.minimum = 1;
          data_integrity_failures = {
            minimum = 0;
            maximum = 0;
          };
        };
      };
    };
    assertions = [
      {
        assertion =
          cfg.lifecycleCycles
          >= 10
          && builtins.all (platform:
            builtins.any (target: target.platform == platform && target.kind == "container" && target.required)
            (builtins.attrValues config.qualification.targets)) ["x86_64-linux" "aarch64-linux"];
        message = "Containers require both native Linux architectures and at least ten lifecycle cycles.";
      }
    ];
  };
}
