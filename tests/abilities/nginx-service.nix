##! Checks native nginx service options and conditional TLS credentials.
{
  lib,
  pkgs,
}: let
  evaluateBase = import ./base-module-evaluation.nix {inherit lib pkgs;};
  environment = lib.abilities.environmentId {
    authority = "test";
    key = "nginx";
    stage = "host";
  };
  credential = key:
    lib.abilities.resourceReference {
      interface = lib.abilities.interfaces.serviceManagement.interfaces.credentialDelivery.identity;
      resource = {
        provider = lib.abilities.instanceId {
          inherit environment;
          key = "credentials";
        };
        inherit key;
      };
      operations = ["observe"];
      lifetime = "persistent";
    };
  evaluate = settings:
    evaluateBase {
      name = "nginx";
      module.aos.services.nginx = settings;
      packages = [pkgs.nginx pkgs.systemd];
      extraModules = [
        {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
          };
        }
      ];
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
      certificate.resource = credential "certificate";
      privateKey.resource = credential "private-key";
    };
  };
  requestsFor = evaluation:
    lib.filterAttrs (name: _: lib.hasPrefix "nginx:" name) evaluation.config.aos.abilities.requests;
  cleartextRequests = requestsFor cleartext;
  tlsRequests = requestsFor tls;
in
  assert requestsFor disabled == {};
  assert cleartextRequests ? "nginx:main-lifecycle";
  assert !(cleartextRequests ? "nginx:main-credentials");
  assert tlsRequests ? "nginx:main-credentials";
  assert tlsRequests ? "nginx:credential-tls-certificate";
  assert tlsRequests ? "nginx:credential-tls-private-key";
  assert builtins.all (assertion: assertion.assertion) cleartext.config.assertions;
  assert builtins.all (assertion: assertion.assertion) tls.config.assertions; true
