##! Baseline Crucible instrumentation over real native nginx activation.
{
  lib,
  mkSystem,
  pkgs,
}: let
  base = import ./ability-native-activation.nix {
    inherit lib mkSystem pkgs;
  };
  fixture = import ./_ability-runtime-reference.nix {
    inherit lib mkSystem pkgs;
  };
  disabledSystem = fixture.runtimeSystem;
  enabledSystem = mkSystem (
    fixture.runtimeModules
    ++ [
      {aos.profiles.abilityCrucible.enable = true;}
    ]
  );
  disabledConfig = disabledSystem.config;
  enabledConfig = enabledSystem.config;
  adapterPath = toString pkgs.aos-ability-crucible;
  disabledPackages = map toString disabledConfig.environment.systemPackages;
  enabledPackages = map toString enabledConfig.environment.systemPackages;
  evaluationContract = assert !(disabledConfig.systemd.services ? "aos-ability-crucible");
  assert !(disabledConfig.environment.etc ? "aos/ability-crucible-adapter.json");
  assert !(disabledConfig.environment.etc ? "aos/ability-execution-observer.json");
  assert !(builtins.elem adapterPath disabledPackages);
  assert enabledConfig.systemd.services ? "aos-ability-crucible";
  assert enabledConfig.environment.etc ? "aos/ability-crucible-adapter.json";
  assert enabledConfig.environment.etc ? "aos/ability-execution-observer.json";
  assert builtins.elem adapterPath enabledPackages;
  assert enabledConfig.systemd.services."aos-ability-crucible".serviceConfig.RuntimeDirectory == "aos-instrumentation";
  assert enabledConfig.systemd.services."aos-ability-crucible".serviceConfig.RuntimeDirectoryMode == "0700"; true;
in
  assert evaluationContract;
    base
    // {
      name = "ability-crucible-baseline";
      machines.runtime =
        base.machines.runtime
        // {
          system = enabledSystem;
          extraClosures =
            base.machines.runtime.extraClosures
            ++ [disabledConfig.system.build.toplevel];
        };
      testScript =
        base.testScript
        + # python
        ''
          # The full native-activation flight above supplies the real nginx
          # update, independent HTTP/configuration probes, retained state, and
          # inspector timeline. Verify its optional instrumentation profile and
          # the disabled system's realized closure independently.
          runtime.succeed(
              "systemctl is-active --quiet aos-ability-crucible.service"
          )
          runtime.succeed(
              "test \"$(stat -c '%U:%G:%a' /run/aos-instrumentation)\" "
              "= root:root:700"
          )
          runtime.succeed(
              f"{JQ} -e "
              "'.schema == \"aos.ability-crucible-adapter/v1\" "
              "and .required_instruction_abi == 1 "
              "and .required_marker_kinds == "
              "[\"assertion\",\"coverage\",\"event\",\"lifecycle\"]' "
              "/etc/aos/ability-crucible-adapter.json"
          )
          runtime.succeed(
              f"{JQ} -e "
              "'.schema == \"aos.ability-execution-observer/v1\" "
              "and .socket == "
              "\"/run/aos-instrumentation/controller.sock\"' "
              "/etc/aos/ability-execution-observer.json"
          )
          runtime.fail(
              f"{NIX_BIN}/nix-store --query --requisites "
              "${disabledConfig.system.build.toplevel} "
              f"| {pkgs.grep}/bin/grep -E "
              "'(aos-ability-crucible|crucible-guest)'"
          )
        '';
    }
