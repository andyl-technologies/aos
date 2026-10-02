##! Checks native nginx service selection and conditional TLS delivery.
{
  lib,
  pkgs,
}: let
  evaluate = settings:
    lib.evalPackageModules {
      scope = ["test" "nginx"];
      packages = [pkgs.nginx];
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
  builtins.all (value: value) (builtins.attrValues (import ../../pkgs/networking/_nginx/native-tests.nix {inherit lib disabled cleartext tls;}))
