##! Checks native test resources and the behaviors exercised by VM fixtures.
let
  lib = import ../../lib {system = "x86_64-linux";};
  package = {
    type = "derivation";
    name = "fixture";
    outPath = import ./_fixture-payload.nix "fixture";
    meta.mainProgram = "fixture";
  };
  evaluation = {
    inherit lib;
    specialArgs = {
      inherit package;
      dependencies = {
        coreutils = package;
        bash = package;
        socat = package;
        systemd = package;
        aos = package;
        nix = package;
        zstd = package;
        ability-package-smoke-provider = package;
      };
    };
    modules = [
      ../../lib/effects/module.nix
      ../../pkgs/system/_service-management/module.nix
      ../../pkgs/filesystem/_aos-filesystem-provider/module.nix
      ../../pkgs/networking/_nftables/module.nix
      ../../pkgs/system/_kmod-abilities/module.nix
      ../../pkgs/tools/_aos-kernel-tunable-provider/module.nix
      ../../pkgs/tests/_desired-config-test/module.nix
      ../../pkgs/tests/_desired-prune-test/module.nix
      ../../pkgs/tests/_landlock-argv-test/module.nix
      ../../pkgs/tests/_aos-credential-delivery-test/module.nix
      ../../pkgs/tests/_test-http-server/module.nix
      ../../pkgs/tests/_test-static-cache-server/module.nix
      ../../pkgs/tests/_aos-test-agent/module.nix
      ../../pkgs/tests/_upgrade-transition-fixture/module.nix
      ../../pkgs/tests/_aos-zfs-test-pool/module.nix
      ../../pkgs/tests/_aos-registry-server/module.nix
      ../../pkgs/tests/_ability-package-smoke/module.nix
      ../../pkgs/tests/_aos-ability-boundary-observer/module.nix
      ../../pkgs/tools/_aos-ability-crucible/module.nix
      ({lib, ...}: {
        options.assertions = lib.mkOption {
          type = lib.types.listOf lib.types.anything;
          default = [];
        };
        config = {
          aos-registry-server.enable = true;
          aos.tests.executionObserver.mode = "external-test-mount";
          aos.tests.zfsPool.enable = true;
          aos-credential-delivery-test.encrypted = true;
          upgrade-transition-fixture.generation = "updated";
          aos.abilities = {
            serviceManagement.operations.realize.handler.program = package;
            configuration.operations.file.handler.program = package;
            credential.operations.deliver.handler.program = package;
            networkPolicy.operations.ruleset.handler.program = package;
            packageSmoke.operations.echo.effects.sample.input = {};
          };
        };
      })
    ];
  };
  evaluated = lib.evalModules evaluation;
  initial = lib.evalModules (evaluation
    // {
      modules = evaluation.modules ++ [{upgrade-transition-fixture.generation = lib.mkForce "initial";}];
    });
  initialNodes = builtins.attrValues initial.config.aos.activation.graph.nodes;
  initialUpgrade = builtins.head (builtins.filter (node: builtins.elem "upgrade-transition-fixture.aos-upgrade-removed" node.identity) initialNodes);
  graph = evaluated.config.aos.activation.graph;
  nodes = builtins.attrValues graph.nodes;
  select = operation: effect: builtins.head (builtins.filter (node: builtins.elem operation node.identity && builtins.elem effect node.identity) nodes);
  desired = select "realize" "desired-config-test.main";
  argv = select "realize" "landlock-argv-test.main";
  credential = select "realize" "aos-credential-delivery-test.main";
  delivery = select "deliver" "aos-credential-delivery-test";
  upgrade = select "realize" "upgrade-transition-fixture.aos-upgrade-test-marker";
  smoke = select "echo" "sample";
in {
  observerUsesExplicitNativeSocket = evaluated.config.aos.execution.observer.socketPath == "/run/aos-instrumentation/controller.sock";
  crucibleRetainsReadiness = builtins.length (select "realize" "ability-crucible.adapter").input.lifecycle.post_start == 1;
  desiredWaitsForStateAndConfig = builtins.length desired.dependencies == 2;
  stateSurvivesPruning = (select "persistentAllocate" "desired-prune-test-state").lifetime == "persistent";
  argvPreservesEscaping = builtins.tail (builtins.head argv.input.lifecycle.start).executable.arguments == ["plain" "two words" "semi;colon" ''quote"inner'' "colon:value"];
  encryptedSourceDeliveredOnce = delivery.input.encrypted && !(builtins.head credential.input.credentials.views).encrypted;
  registryWaitsForRenderedConfiguration = builtins.length (select "realize" "aos-registry-server.cache").dependencies >= 5;
  upgradeWaitsForNativePolicy = builtins.length upgrade.dependencies == 2;
  upgradeMergesHostTunables = (select "ensure" "settings").input.values."net.ipv4.tcp_keepalive_time" == "300";
  initialUpgradeNeedsNoTunableEffect =
    builtins.length initialUpgrade.dependencies
    == 1
    && !(builtins.any (node: builtins.elem "kernelTunables" node.identity) initialNodes);
  zfsWaitsForRequiredModule = builtins.length (select "realize" "zfs-test-pool.pool").dependencies == 1;
  smokePreservesUnicodeAndIntegers = smoke.input.label == "café 東京 😀" && smoke.input.maximum == 9007199254740991 && smoke.input.minimum == (-9007199254740991);
}
