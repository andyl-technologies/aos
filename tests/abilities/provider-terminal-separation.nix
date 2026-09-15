##! Exact-one controller or terminal ownership for production providers.
{
  lib,
  pkgs,
}: let
  evaluation = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      ../../modules/systemd/system.nix
      {
        config.aos.abilities.environment = {
          authority = "test";
          key = "provider-terminal-separation";
          stage = "host";
        };
      }
    ];
    packageModules = [
      {
        name = "systemd";
        module = {
          imports = [
            ../../pkgs/system/_systemd-abilities.nix
            ../../pkgs/system/_systemd-provider.nix
          ];
          config.aos.abilities.instances.manager = {};
        };
      }
      {
        name = "aos-filesystem-provider";
        module = {
          imports = [
            ../../pkgs/filesystem/_aos-filesystem-provider/module.nix
            ../../pkgs/filesystem/_aos-filesystem-provider/provider.nix
          ];
          config.aos.abilities.instances.filesystem = {};
        };
      }
    ];
    specialArgs = {
      inherit pkgs;
      packageName = "systemd";
      artifactLocatorFor = _: throw "separation audit must not resolve an artifact";
      provenance = {
        dependencyOwnersOfAttr = _: _: [];
        ownerOfListAttr = _: _: _: "@test";
      };
    };
  };
  implementations = evaluation.config.aos.abilities.implementations;
  audited = builtins.filter (name:
    lib.hasPrefix "systemd:" name
    || lib.hasPrefix "aos-filesystem-provider:" name)
  (builtins.attrNames implementations);
  hasProvider = implementation: implementation.providerModule != null;
  hasHandler = implementation: implementation.handlerDescriptor != null;
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
  assert implementations."aos-filesystem-provider:filesystem-entry".handlerDescriptor == null;
  assert implementations."aos-filesystem-provider:storage-allocation".handlerDescriptor == null;
  assert implementations."aos-filesystem-provider:persistent-storage-allocation".handlerDescriptor == null;
  assert implementations."aos-filesystem-provider:storage-view".handlerDescriptor == null; true
