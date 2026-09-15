##! Exact-one controller or terminal ownership for production providers.
{
  lib,
  pkgs,
}: let
  selectedSystemdProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "systemd-packaged-unit";
  };
  evaluation = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      ../../modules/systemd/system.nix
      {
        config.aos.abilities = {
          environment = {
            authority = "test";
            key = "provider-terminal-separation";
            stage = "host";
          };
          instances."systemd:manager" = {};
        };
      }
    ];
    packageModules = [
      {
        name = "systemd";
        inherit (pkgs.systemd) version;
        module = pkgs.systemd.module + "/module.nix";
      }
    ];
    selectedProviderModules = [selectedSystemdProvider];
    specialArgs = {
      inherit pkgs;
      artifactLocatorFor = _: throw "separation audit must not resolve an artifact";
      provenance = {
        dependencyOwnersOfAttr = _: _: [];
        ownerOfListAttr = _: _: _: "@test";
      };
    };
  };
  implementations = evaluation.config.aos.abilities.implementations;
  audited = builtins.filter (name: lib.hasPrefix "systemd:" name) (builtins.attrNames implementations);
  hasProvider = implementation: implementation.providerModule != null;
  hasHandler = implementation: implementation.handlerDescriptor != null;
  serviceTerminal = implementations."systemd:systemd-service-effects";
  exactlyOne = name: let
    implementation = implementations.${name};
  in
    hasProvider implementation != hasHandler implementation;
in
  assert audited != [];
  assert builtins.all exactlyOne audited;
  assert implementations."systemd:systemd-packaged-unit".handlerDescriptor == null;
  assert implementations."systemd:network-readiness".handlerDescriptor == null;
  assert implementations."systemd:filesystem-readiness".handlerDescriptor == null;
  assert serviceTerminal.qualification.adapter == "service-management";
  assert serviceTerminal.qualification.observationKind == "systemd";
  assert serviceTerminal.qualification.scope == "host-manager";
  assert serviceTerminal.qualification.observer.entryPoint == "bin/aos-systemd-service-effects-observer"; true
