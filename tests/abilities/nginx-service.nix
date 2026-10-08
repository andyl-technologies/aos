##! Checks native nginx service selection and conditional TLS delivery.
{
  lib,
  pkgs,
}: let
  evaluate = settings:
    lib.evalPackageModules {
      scope = ["test" "nginx"];
      packages = [pkgs.nginx pkgs.systemd pkgs.aos-init-provider];
      operatorModules = [{aos.services.nginx = settings;}];
    };
  disabled = evaluate {};
  cleartext = evaluate {
    enable = true;
    virtualHosts.local = {};
  };
  tls = evaluate {
    enable = true;
    virtualHosts.local.tls.enable = true;
    tlsCredentials = {
      certificate.name = "certificate";
      privateKey.name = "private-key";
    };
  };
in
  assert disabled.config.aos.abilities.serviceManagement.operations.realize.effects ? dbus;
  assert disabled.config.aos.abilities.serviceManagement.operations.realize.effects.dbus.input.bootstrap;
  assert disabled.config.aos.abilities.serviceManagement.operations.realize.handler.program.outPath == pkgs.systemd.handlers.outPath;
    builtins.all (value: value) (builtins.attrValues (import ../../pkgs/networking/_nginx/native-tests.nix {inherit lib disabled cleartext tls;}))
