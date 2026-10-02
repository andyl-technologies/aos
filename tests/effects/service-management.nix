##! Checks the shared native service schema, references, and manager ownership.
let
  lib = import ../../lib {system = "x86_64-linux";};
  payload = import ./_fixture-payload.nix;
  program = {
    type = "derivation";
    name = "native-service-fixture";
    outPath = toString (payload "native-service-fixture");
    meta.mainProgram = "native-service-fixture";
  };
  lifecycle = {
    description = "Native service fixture";
    execution_model = "foreground";
    environment_files = [];
    condition = [];
    pre_start = [];
    start = [
      {
        executable = {
          path = "${program.outPath}/bin/example";
          arguments = [];
        };
        ignore_failure = false;
      }
    ];
    post_start = [];
    stop = [];
    post_stop = [];
    restart = "on-failure";
    restart_delay_millis = 1000;
    remain_after_exit = false;
    start_timeout_millis = 90000;
    stop_timeout_millis = 90000;
  };
  evaluate = modules:
    lib.evalModules {
      inherit lib;
      modules = [../../lib/effects/module.nix ../../pkgs/system/_service-management/module.nix] ++ modules;
    };
  configured = evaluate [
    {
      aos.services.example = {
        enable = true;
        inherit lifecycle;
      };
      aos.abilities.serviceManagement.operations.realize.handler = {inherit program;};
    }
  ];
  effect = configured.config.aos.abilities.serviceManagement.operations.realize.effects.example;
  projected = configured.config.aos.abilities.serviceManagement.operations.realize.documentation.inputType;
  extended = evaluate [
    {
      aos.abilities.serviceManagement.operations.realize.input.options.operatorSetting = lib.mkOption {
        type = lib.types.str;
        default = "merged";
      };
    }
    {
      aos.services.example = {
        enable = true;
        inherit lifecycle;
        operatorSetting = "configured";
      };
      aos.abilities.serviceManagement.operations.realize.handler = {inherit program;};
    }
  ];
  collision = evaluate [
    {
      aos.services = {
        first = {
          enable = true;
          inherit lifecycle;
          service = "same";
        };
        second = {
          enable = true;
          inherit lifecycle;
          service = "same";
        };
      };
      aos.abilities.serviceManagement.operations.realize.handler = {inherit program;};
    }
  ];
  singletonCollision = evaluate [
    {
      aos.services = {
        first = {
          enable = true;
          inherit lifecycle;
          service = "same";
        };
        second = {
          enable = true;
          inherit lifecycle;
          service = "same";
          instantiation.kind = "singleton";
        };
      };
      aos.abilities.serviceManagement.operations.realize.handler = {inherit program;};
    }
  ];
  managerCollision = evaluate [
    {
      aos.services = builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = {
          enable = true;
          inherit lifecycle;
          service = name;
          manager_identity = {
            name = "same";
            aliases = [];
          };
        };
      }) ["first" "second"]);
      aos.abilities.serviceManagement.operations.realize.handler = {inherit program;};
    }
  ];
  aliasCollision = evaluate [
    {
      aos.services = {
        first = {
          enable = true;
          inherit lifecycle;
          service = "first";
          manager_identity = {
            name = "override";
            aliases = ["second"];
          };
        };
        second = {
          enable = true;
          inherit lifecycle;
          service = "second";
        };
      };
      aos.abilities.serviceManagement.operations.realize.handler = {inherit program;};
    }
  ];
  invalidMode = evaluate [
    {
      aos.services.example = {
        enable = true;
        inherit lifecycle;
        identity = {
          principal = "example";
          primary_group = "example";
          supplementary_groups = [];
          ephemeral = false;
          file_creation_mask = "0999";
        };
      };
      aos.abilities.serviceManagement.operations.realize.handler = {inherit program;};
    }
  ];
  signalCondition = evaluate [
    {
      aos.services.example = {
        enable = true;
        inherit lifecycle;
        conditions.all = [
          {
            kind = "path";
            predicate = "exists";
            path = "/run/example";
            negated = false;
          }
        ];
      };
      aos.abilities.serviceManagement.operations.realize.handler = {inherit program;};
    }
  ];
in {
  noManualInstances = assert builtins.attrNames configured.config.aos.abilities.serviceManagement.operations.realize.effects == ["example"]; true;
  sharedInputExtension = assert extended.config.aos.services.example.operatorSetting == "configured";
  assert extended.config.aos.abilities.serviceManagement.operations.realize.effects.example.input.operatorSetting == "configured"; true;
  unusedContractNeedsNoHandler = assert (evaluate []).config.aos.activation.graph.order == []; true;
  typedExecution = assert effect.input.instance == "example";
  assert effect.execution.program == program;
  assert effect.input.lifecycle.configuration_change_action == "restart"; true;
  recursivePortableSchema = assert projected.fields.watchdog.value.fields.timeout_millis.min == 1;
  assert projected.fields.socket_activation.value.fields.sockets.element.fields.mode.value.max_length == 4; true;
  ambiguousManagerNamesFail = assert !(builtins.tryEval (builtins.deepSeq collision.config.aos.activation.graph true)).success; true;
  explicitSingletonCollisionFails = assert !(builtins.tryEval (builtins.deepSeq singletonCollision.config.aos.activation.graph true)).success; true;
  managerOverrideCollisionFails = assert !(builtins.tryEval (builtins.deepSeq managerCollision.config.aos.activation.graph true)).success; true;
  managerAliasCollisionFails = assert !(builtins.tryEval (builtins.deepSeq aliasCollision.config.aos.activation.graph true)).success; true;
  invalidModeFails = assert !(builtins.tryEval (builtins.deepSeq invalidMode.config.aos.activation.graph true)).success; true;
  taggedPathCondition = assert (builtins.head signalCondition.config.aos.services.example.conditions.all).predicate == "exists"; true;
}
