##! Checks native etcd TLS selection, storage, and configuration validation.
{
  lib,
  self,
}: let
  evaluate = settings: let
    result = lib.evalPackageModules {
      scope = ["test" "etcd"];
      packages = [self];
      operatorModules = [{aos.etcd = settings;}];
    };
  in
    result.config // {_assertions = result.assertions;};
  tls = prefix: {
    enable = true;
    certificate.name = "${prefix}-certificate";
    privateKey.name = "${prefix}-private-key";
    trustedCa.name = "${prefix}-trusted-ca";
  };
  evaluateTls = client: peer:
    evaluate {
      enable = true;
      client = {
        listenUrls = [
          "${
            if client
            then "https"
            else "http"
          }://127.0.0.1:2379"
        ];
        advertiseUrls = [
          "${
            if client
            then "https"
            else "http"
          }://127.0.0.1:2379"
        ];
        tls =
          if client
          then tls "client"
          else {};
      };
      peer = {
        listenUrls = [
          "${
            if peer
            then "https"
            else "http"
          }://127.0.0.1:2380"
        ];
        advertiseUrls = [
          "${
            if peer
            then "https"
            else "http"
          }://127.0.0.1:2380"
        ];
        tls =
          if peer
          then tls "peer"
          else {};
      };
      cluster.members.default.peerUrls = [
        "${
          if peer
          then "https"
          else "http"
        }://127.0.0.1:2380"
      ];
    };
  assertionsHold = config: builtins.all (value: value.assertion) config._assertions;
  countCredentials = config: builtins.length (builtins.attrNames config.aos.abilities.credential.operations.deliver.effects);
  plain = evaluateTls false false;
  both = evaluateTls true true;
  disabled = evaluate {};
in {
  tlsSelection = assert countCredentials plain == 0;
  assert countCredentials (evaluateTls true false) == 3;
  assert countCredentials (evaluateTls false true) == 3;
  assert countCredentials both == 6;
  assert assertionsHold both; true;
  structuredConfiguration = assert plain.aos.abilities.configuration.operations.file.effects.etcd.input.format == "json";
  assert both.aos.abilities.configuration.operations.file.effects.etcd.input.value ? "client-transport-security";
  assert both.aos.abilities.configuration.operations.file.effects.etcd.input.value ? "peer-transport-security"; true;
  persistentStorage = assert plain.aos.abilities.filesystem.operations.directory.effects.etcd-data.lifetime == "persistent";
  assert builtins.length plain.aos.services."etcd.main".storage.mounts == 2; true;
  disabledEffects = assert disabled.aos.abilities.serviceManagement.operations.realize.effects == {};
  assert disabled.aos.abilities.configuration.operations.file.effects == {}; true;
  invalidMember = assert !(assertionsHold (evaluate {name = "missing";})); true;
  missingCredentials = assert !(assertionsHold (evaluate {
    client = {
      listenUrls = ["https://localhost:2379"];
      advertiseUrls = ["https://localhost:2379"];
      tls.enable = true;
    };
  })); true;
  duplicateEndpoints = assert !(assertionsHold (evaluate {client.listenUrls = ["http://localhost:2379" "http://localhost:2379"];})); true;
}
