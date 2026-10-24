##! Exercises the actual Root credential expression and assertion without builds.
##!
##! This deliberately evaluates only the production public trust wiring. It
##! creates no usable resource bank, native owner, file, private key or image.
{lib}: let
  inspect = selected: policy: publicKey: let
    production = import ../../modules/sandbox/policy-authority.nix {
      inherit lib;
      pkgs = {};
      config.aos.sandbox = {
        policyAuthority = {
          enable = true;
          environmentProvision = null;
          credentials =
            lib.genAttrs
            (builtins.attrNames production.options.aos.sandbox.policyAuthority.credentials)
            (_: null);
        };
        cacheSignerService.credentials.memoryCeiling = null;
        resourceBank.policy =
          if selected
          then {rootReceiving = {};}
          else null;
        hostBroker.credentials = {
          rootNoApplyFloorPublicKey = null;
          brokerPlanPolicy = null;
          brokerPlanPublicKey = null;
          brokerRevocationScope = null;
          ownershipLeasePolicy = policy;
          ownershipLeasePublicKey = publicKey;
        };
        mountBroker.credentials = {
          brokerPlanPolicy = null;
          brokerPlanPublicKey = null;
          brokerRevocationScope = null;
        };
      };
    };
    # mkIf remains an explicit module definition here. Read its real content,
    # rather than replacing the production condition with a copied predicate.
    actual = assert production.config._type == "if" && production.config._condition;
      production.config._value;
    trustAssertion =
      builtins.filter
      (item: item.message == "selected Root receiving requires its own installed public Ownership lease policy and key from the existing Host trust configuration")
      actual.assertions;
  in {
    accepted =
      builtins.length trustAssertion
      == 1
      && (builtins.head trustAssertion).assertion;
    credentials = actual.systemd.services.aos-sandbox-policy-authorityd.serviceConfig.LoadCredential;
  };
  absent = inspect true null null;
  missingPolicy = inspect true null "fixture-public";
  missingKey = inspect true "fixture-policy" null;
  complete = inspect true "fixture-policy" "fixture-public";
  ordinary = inspect false null null;
in
  !absent.accepted
  && !missingPolicy.accepted
  && !missingKey.accepted
  && complete.accepted
  && complete.credentials
  == [
    "ownership-lease-policy.cbor:/run/credentials/@system/fixture-policy"
    "ownership-lease-public-key:/run/credentials/@system/fixture-public"
  ]
  && ordinary.accepted
  && ordinary.credentials == []
