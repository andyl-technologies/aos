##! Exercises the actual fixed Root Delete credential wiring without builds.
{lib}: let
  mountOptions = (import ../../modules/sandbox/mount-broker.nix {
    inherit lib;
    pkgs = {};
    config = {};
  }).options.aos.sandbox.mountBroker.credentials;
  hostOptions = (import ../../modules/sandbox/host-broker.nix {
    inherit lib;
    pkgs = {};
    config = {};
  }).options.aos.sandbox.hostBroker.credentials;
  credentialDefaults = options: lib.mapAttrs (_: option: option.default) options;
  mount = {
    brokerPlanPolicy = "fixture-mount-policy";
    brokerPlanPublicKey = "fixture-mount-public";
    brokerRevocationScope = "fixture-mount-scope";
  };
  root = {
    deleteHostSessionManifest = "fixture-host";
    deleteMountSessionManifest = "fixture-mount";
    deleteNetworkSessionManifest = "fixture-network";
  };
  controller = {
    brokerSessionHostManifest = "fixture-host";
    brokerSessionMountManifest = "fixture-mount";
    brokerSessionNetworkManifest = "fixture-network";
  };
  messages = [
    "Root Delete requires the Host, Mount and Network public session manifests together"
    "Root Delete requires the selected confined Root and the same independently provisioned Controller broker manifests"
    "Root broker comparison requires Mount's same public broker-plan policy, key, and revocation scope"
  ];
  inspect = credentials: controllerCredentials: mountCredentials: confined: selected: let
    production = import ../../modules/sandbox/policy-authority.nix {
      inherit lib;
      pkgs.aos-sandboxd = "fixture-normal-root";
      config = {
        aos.security.selinux = {
          enable = confined;
          bootMode = "immutable-stage0";
        };
        aos.sandbox = {
          policyAuthority = {
            enable = true;
            package = "fixture-normal-root";
            environmentProvision = null;
            credentials = lib.genAttrs
              (builtins.attrNames production.options.aos.sandbox.policyAuthority.credentials)
              (_: null) // credentials;
          };
          resourceBank.policy = if selected then {rootReceiving = {};} else null;
          controllerService.credentials = controllerCredentials;
          cacheSignerService.credentials.memoryCeiling = null;
          # Direct fixture imports bypass discovery; retain the genuine
          # public credential defaults rather than omitting a required role.
          hostBroker.credentials = credentialDefaults hostOptions;
          mountBroker.credentials = credentialDefaults mountOptions // mountCredentials;
        };
      };
    };
    actual = assert production.config._type == "if" && production.config._condition;
      production.config._value;
    assertions = builtins.filter
      (item: builtins.elem item.message messages)
      actual.assertions;
  in {
    accepted = builtins.length assertions == 3
      && lib.all (item: item.assertion) assertions;
    loaded = actual.systemd.services.aos-sandbox-policy-authorityd.serviceConfig.LoadCredential;
  };
  complete = inspect root controller mount true true;
  absent = inspect {} {} {} false false;
  partial = inspect {inherit (root) deleteHostSessionManifest;} controller mount true true;
  foreign = inspect root (controller // {brokerSessionMountManifest = "foreign";}) mount true true;
  unconfined = inspect root controller mount false true;
  unselected = inspect root controller mount true false;
  missingMount = inspect root controller {} true true;
  missingMountPolicy = inspect root controller (mount // {brokerPlanPolicy = null;}) true true;
  missingMountKey = inspect root controller (mount // {brokerPlanPublicKey = null;}) true true;
  missingMountScope = inspect root controller (mount // {brokerRevocationScope = null;}) true true;
in
  complete.accepted
  && complete.loaded == [
    "delete-host-session-manifest-v2:/run/credentials/@system/fixture-host"
    "delete-mount-session-manifest-v2:/run/credentials/@system/fixture-mount"
    "delete-network-session-manifest-v2:/run/credentials/@system/fixture-network"
    "mount-broker-plan-policy.cbor:/run/credentials/@system/fixture-mount-policy"
    "mount-broker-plan-public-key:/run/credentials/@system/fixture-mount-public"
    "mount-broker-revocation-scope:/run/credentials/@system/fixture-mount-scope"
  ]
  && absent.accepted && absent.loaded == []
  && !partial.accepted
  && !foreign.accepted
  && !unconfined.accepted
  && !unselected.accepted
  && !missingMount.accepted
  && !missingMountPolicy.accepted
  && !missingMountKey.accepted
  && !missingMountScope.accepted
