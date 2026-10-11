##! Seeds only literal files consumed by selected early native services.
let
  lib = import ../../lib {system = "x86_64-linux";};
  lifecycle = {
    description = "Bootstrap configuration consumer";
    execution_model = "foreground";
    environment_files = [];
    condition = [];
    pre_start = [];
    start = [
      {
        executable = {
          path = "${import ./_fixture-payload.nix "bootstrap-consumer"}/bin/consumer";
          arguments = [];
        };
        ignore_failure = false;
      }
    ];
    post_start = [];
    stop = [];
    post_stop = [];
    restart = "never";
    restart_delay_millis = 0;
    remain_after_exit = false;
    start_timeout_millis = 90000;
    stop_timeout_millis = 90000;
  };
  evaluate = settings:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../lib/effects/module.nix
        ../../pkgs/system/_service-management/module.nix
        ({config, ...}: {
          aos.abilities.configuration.operations.file.effects.policy.input = {
            path = "/etc/bootstrap/policy.conf";
            content = "canonical policy\n";
            mode = "0640";
          };
          aos.services.bus = {
            inherit lifecycle;
            enable = true;
            bootstrap = true;
            activationInputs = [config.aos.abilities.configuration.operations.file.effects.policy.outputs.resource];
          };
        })
        settings
      ];
    };
  project = settings:
    import ../../pkgs/system/_systemd-abilities/bootstrap-config.nix {
      inherit lib;
      config = (evaluate settings).config;
    };
  rejects = settings: let
    projected = project settings;
  in
    !(builtins.tryEval (builtins.deepSeq projected true)).success;
  original = project {};
  changed = project {
    aos.abilities.configuration.operations.file.effects.policy.input = {
      content = lib.mkForce "operator policy\n";
      mode = lib.mkForce "0600";
      owner = "root";
      group = "root";
    };
  };
  pathReference = project ({config, ...}: {
    aos.services.bus.activationInputs = lib.mkForce [config.aos.abilities.configuration.operations.file.effects.policy.outputs.path];
  });
  repeatedReference = project ({config, ...}: {
    aos.services.second = {
      inherit lifecycle;
      enable = true;
      bootstrap = true;
      activationInputs = [config.aos.abilities.configuration.operations.file.effects.policy.outputs.resource];
    };
  });
  foreignReference = project ({config, ...}: {
    aos.abilities.device.operations.present.effects.foreign.input.path = "/dev/null";
    aos.services.bus.activationInputs = lib.mkForce [config.aos.abilities.device.operations.present.effects.foreign.outputs.resource];
  });
in {
  canonicalBytesAndMode =
    original.filesystemEntries."bootstrap/policy.conf"
    == {
      kind = "text";
      mode = "0640";
      text = "canonical policy\n";
    };
  canonicalOwnerRetained = original.ownership.filesystemEntries."bootstrap/policy.conf" == (evaluate {}).config.aos.abilities.configuration.operations.file.effects.policy.contract.owner;
  literalFragmentsPreserveOrder =
    (project {
      aos.abilities.configuration.operations.file.effects.policy.input = {
        content = lib.mkForce null;
        fragments = ["first\n" "second\n"];
      };
    }).filesystemEntries."bootstrap/policy.conf".text
    == "first\nsecond\n";
  operatorPolicyProjectedOnce =
    builtins.attrNames changed.filesystemEntries
    == ["bootstrap/policy.conf"]
    && changed.filesystemEntries."bootstrap/policy.conf".text == "operator policy\n"
    && changed.filesystemEntries."bootstrap/policy.conf".mode == "0600";
  pathOutputAlsoSelectsCanonicalFile = pathReference == original;
  sharedConsumerDoesNotDuplicateFile = repeatedReference == original;
  disabledConsumerDoesNotSeed = (project {aos.services.bus.enable = lib.mkForce false;}).filesystemEntries == {};
  ordinaryConsumerDoesNotSeed = (project {aos.services.bus.bootstrap = lib.mkForce false;}).filesystemEntries == {};
  managerOwnedConsumerAlsoSeeds =
    project {
      aos.services.bus = {
        bootstrap = lib.mkForce false;
        activationOwner = "manager";
      };
    }
    == original;
  disabledFileDoesNotSeed = (project {aos.abilities.configuration.operations.file.effects.policy.enable = false;}).filesystemEntries == {};
  foreignReferenceDoesNotAdoptFile = foreignReference.filesystemEntries == {};
  credentialFragmentRejected = rejects {
    aos.abilities.configuration.operations.file.effects.policy.input = {
      content = lib.mkForce null;
      fragments = [{credentialPath = "/run/credentials/secret";}];
    };
  };
  deferredFragmentRejected = rejects ({config, ...}: {
    aos.abilities.device.operations.present.effects.foreign.input.path = "/dev/null";
    aos.abilities.configuration.operations.file.effects.policy.input = {
      content = lib.mkForce null;
      fragments = [config.aos.abilities.device.operations.present.effects.foreign.outputs.resource];
    };
  });
  structuredEncodingRejected = rejects {
    aos.abilities.configuration.operations.file.effects.policy.input = {
      format = "json";
      value = {policy = true;};
    };
  };
  nonRootOwnerRejected = rejects {aos.abilities.configuration.operations.file.effects.policy.input.owner = "messagebus";};
  nonRootGroupRejected = rejects {aos.abilities.configuration.operations.file.effects.policy.input.group = "messagebus";};
  outsideEtcRejected = rejects {aos.abilities.configuration.operations.file.effects.policy.input.path = lib.mkForce "/run/bootstrap.conf";};
  escapingDestinationRejected = rejects {aos.abilities.configuration.operations.file.effects.policy.input.path = lib.mkForce "/etc/../run/bootstrap.conf";};
  emptyDestinationRejected = rejects {aos.abilities.configuration.operations.file.effects.policy.input.path = lib.mkForce "/etc/";};
  emptyComponentRejected = rejects {aos.abilities.configuration.operations.file.effects.policy.input.path = lib.mkForce "/etc/bootstrap//policy.conf";};
  dotComponentRejected = rejects {aos.abilities.configuration.operations.file.effects.policy.input.path = lib.mkForce "/etc/./bootstrap.conf";};
  duplicateDestinationRejected = rejects ({config, ...}: {
    aos.abilities.configuration.operations.file.effects.other.input = {
      path = "/etc/bootstrap/policy.conf";
      content = "foreign bytes\n";
    };
    aos.services.bus.activationInputs = [config.aos.abilities.configuration.operations.file.effects.other.outputs.resource];
  });
}
