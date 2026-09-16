##! Fixed-point checks for the package-owned upgrade transition fixtures.
{
  lib,
  pkgs,
}: let
  evaluate = configuration:
    lib.evalModules {
      inherit lib;
      modules =
        ([
        ../../modules/abilities/default.nix
        {
          aos.abilities.environment = {
            authority = "test";
            key = "upgrade-transition";
            stage = "host";
          };
        }
        configuration
      ])
        ++ builtins.map lib.authenticatedModule (([
        {
          name = "test-http-server";
          version = pkgs.test-http-server.version;
          module = pkgs.test-http-server.module + "/module.nix";
        }
        {
          name = "upgrade-transition-fixture";
          version = pkgs.upgrade-transition-fixture.version;
          module = pkgs.upgrade-transition-fixture.module + "/module.nix";
        }
      ]));

    };
  configured = generation:
    evaluate {
      test-http-server = {
        enable = true;
        port = 8000;
      };
      upgrade-transition-fixture = {
        enable = true;
        inherit generation;
      };
    };
  disabled = evaluate {
    test-http-server.enable = false;
    upgrade-transition-fixture.enable = false;
  };
  initial = configured "initial";
  updated = configured "updated";
  initialRequests = initial.config.aos.abilities.requests;
  updatedRequests = updated.config.aos.abilities.requests;
  initialLifecycle = initialRequests."upgrade-transition-fixture:aos-upgrade-removed-lifecycle".parameters;
  updatedLifecycle = updatedRequests."upgrade-transition-fixture:aos-upgrade-test-marker-lifecycle".parameters;
  httpLifecycle = updatedRequests."test-http-server:main-lifecycle".parameters;
  resultReference = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  portableOptionTree = options:
    builtins.all
    (name: let
      option = options.${name};
    in
      if option ? type
      then option.type ? _abilitySchema
      else portableOptionTree option)
    (builtins.attrNames options);
in
  assert disabled.config.aos.abilities.requests == {};
  assert disabled.config.aos.abilities.requirementTemplates == initial.config.aos.abilities.requirementTemplates;
  assert initialRequests."upgrade-transition-fixture:ingress".parameters.endpoints == [];
  assert updatedRequests."upgrade-transition-fixture:ingress".parameters.endpoints
  == [
    {
      transport = "tcp";
      port = 8443;
    }
  ];
  assert initialRequests."upgrade-transition-fixture:kernel-tunables".parameters.values == {};
  assert updatedRequests."upgrade-transition-fixture:kernel-tunables".parameters.values
  == {"net.ipv4.tcp_keepalive_time" = "300";};
  assert initialLifecycle.service == "aos-upgrade-removed";
  assert builtins.length initialLifecycle.stop == 1;
  assert updatedLifecycle.service == "aos-upgrade-test-marker";
  assert updatedLifecycle.stop == [];
  assert httpLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "test-http-server";};
        entry_point = "bin/test-http-server";
        arguments = [
          "--port=8000"
          (resultReference "test-http-server:content" "storage-path")
        ];
      };
      ignore_failure = false;
    }
  ];
  assert updatedRequests."test-http-server:content".parameters
  == {
    mode = "0755";
    name = "content";
    purpose = "state";
  };
  assert portableOptionTree updated.options.test-http-server;
  assert portableOptionTree updated.options.upgrade-transition-fixture; true
