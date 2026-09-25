##! lib/testing/sandbox-network-inspector-guard.nix — closed inspector unit guard checks
{
  lib,
  mkSystem,
  pkgs,
}: let
  inspectorUnitName = "aos-sandbox-network-namespace-inspector@.service";
  inspectorServiceName = "aos-sandbox-network-namespace-inspector@";

  inspectorSystem = overrides:
    mkSystem {
      modules = [
        ../../systems/server.nix
        {aos.sandbox.networkInspector.enable = true;}
        overrides
      ];
      systemName = "sandbox-network-inspector-guard-check";
    };

  source = inspectorSystem {};
  withoutSetId = inspectorSystem {
    systemd.services.${inspectorServiceName}.serviceConfig.RestrictSUIDSGID = lib.mkForce false;
  };
  withoutRingFilter = inspectorSystem {
    systemd.services.${inspectorServiceName}.serviceConfig.SystemCallFilter = lib.mkForce [];
  };

  assertionFor = system: message:
    builtins.filter
    (entry: lib.hasInfix message entry.message)
    system.config.assertions;
  holds = system: message: expected: let
    matches = assertionFor system message;
  in
    builtins.length matches == 1
    && (builtins.head matches).assertion == expected;

  unitText = source.config.systemd.units.${inspectorUnitName}.text;
  ringCalls = ["io_uring_setup" "io_uring_enter" "io_uring_register"];
  passed =
    holds source "remains unavailable until SBX-P0-09" false
    && holds source "inherited AOS no-set-ID guard" true
    && holds source "reject io_uring creation" true
    && holds withoutSetId "inherited AOS no-set-ID guard" false
    && holds withoutRingFilter "reject io_uring creation" false
    && lib.hasInfix "RestrictSUIDSGID=true\n" unitText
    && builtins.all (name: lib.hasInfix "SystemCallFilter=~${name}\n" unitText) ringCalls;
in
  if !passed
  then throw "sandbox Network inspector guard contract failed"
  else
    pkgs.runCommand "sandbox-network-inspector-guard-check" {} ''
      mkdir -p $out
      echo PASS > $out/result
    ''
