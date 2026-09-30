##! Evaluates native ancillary handlers with both timer variants and canonical domain contracts.
let
  repo = ../..;
  lib = import (repo + /lib) {system = "x86_64-linux";};
  package = {
    type = "derivation";
    name = "systemd-fixture";
    outPath = builtins.toString (import ./_fixture-payload.nix "systemd");
    meta.mainProgram = "unused";
  };
  evaluated = lib.evalModules {
    inherit lib;
    specialArgs = {inherit package;};
    modules = [
      (repo + /lib/effects/module.nix)
      (repo + /pkgs/system/_service-management/credential.nix)
      (repo + /pkgs/system/_service-management/mount.nix)
      (repo + /pkgs/system/_systemd-abilities/resource-handlers.nix)
      ({config, ...}: {
        aos.activation.scope = ["ancillary" "host"];
        aos.abilities.swap.operations.ensure.effects.encrypted.input = {
          name = "encrypted";
          source = "/dev/mapper/cryptswap";
        };
        aos.abilities.scheduledActivation.operations.ensure.effects.calendar.input = {
          name = "scrub";
          target = "aos-scrub.service";
          schedule = {
            kind = "calendar";
            expression = "weekly";
          };
          persistent = true;
        };
        aos.abilities.scheduledActivation.operations.ensure.effects.interval.input = {
          name = "sync";
          target = "aos-sync.service";
          schedule = {
            kind = "interval";
            interval_millis = 5000;
          };
        };
        aos.abilities.mount.operations.ensure.effects.bridge.input = {
          name = "GC bridge";
          source = "/var/lib/profiles";
          destination = "/nix/var/nix/gcroots/aos-profiles";
          options = ["bind"];
        };
        aos.abilities.credential.operations.deliver.effects.secret.input.name = "service-secret";
      })
    ];
  };
in let
  graph = evaluated.config.aos.activation.graph;
  nodes = builtins.attrValues graph.nodes;
  selected = builtins.all (node: node.handler.executable == "${package.outPath}/bin/aos-systemd-native-resources") nodes;
  interval = builtins.head (builtins.filter (node: builtins.elem "interval" node.identity) nodes);
in
  assert builtins.length nodes == 5;
  assert selected;
  assert interval.input.schedule.initial_delay_millis == 0;
  assert interval.input.schedule.interval_millis == 5000;
    builtins.deepSeq graph {nativeAncillaryResources = true;}
