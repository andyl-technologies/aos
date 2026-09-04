# Pure evaluation checks for protected sandbox-broker credential provisioning.
{
  lib,
  pkgs,
  mkSystem,
}: let
  authorityCredentials = prefix: {
    brokerPlanPolicy = "${prefix}-plan-policy";
    brokerPlanPublicKey = "${prefix}-plan-public-key";
    brokerRevocationScope = "${prefix}-revocation-scope";
    ownershipLeasePolicy = "${prefix}-lease-policy";
    ownershipLeasePublicKey = "${prefix}-lease-public-key";
    nodeId = "${prefix}-node-id";
    journalMacKey = "${prefix}-journal-mac-key";
  };
  hostCredentialNames = prefix:
    authorityCredentials prefix
    // {backendReadiness = "${prefix}-backend-readiness";};
  expectedAuthority = prefix: [
    "broker-plan-policy.cbor:/run/credentials/@system/${prefix}-plan-policy"
    "broker-plan-public-key:/run/credentials/@system/${prefix}-plan-public-key"
    "broker-revocation-scope:/run/credentials/@system/${prefix}-revocation-scope"
    "journal-mac-key:/run/credentials/@system/${prefix}-journal-mac-key"
    "node-id:/run/credentials/@system/${prefix}-node-id"
    "ownership-lease-policy.cbor:/run/credentials/@system/${prefix}-lease-policy"
    "ownership-lease-public-key:/run/credentials/@system/${prefix}-lease-public-key"
  ];
  expectedHost = prefix:
    ["backend-readiness.json:/run/credentials/@system/${prefix}-backend-readiness"]
    ++ expectedAuthority prefix;
  configured = mkSystem [
    {
      aos.sandbox.hostBroker = {
        enable = true;
        credentials = hostCredentialNames "host";
      };
      aos.sandbox.mountBroker = {
        enable = true;
        credentials = authorityCredentials "mount";
      };
    }
  ];
  observationOnly = mkSystem [
    {
      aos.sandbox.hostBroker = {
        enable = true;
        credentials = authorityCredentials "observe";
      };
    }
  ];
  forceToplevel = modules:
    builtins.tryEval (builtins.toString (mkSystem modules).config.system.build.toplevel);
  missingRejected = !(forceToplevel [{aos.sandbox.hostBroker.enable = true;}]).success;
  partialRejected =
    !(forceToplevel [
      {
        aos.sandbox.mountBroker = {
          enable = true;
          credentials.brokerPlanPolicy = "partial-plan-policy";
        };
      }
    ])
    .success;
  sharedJournalRejected =
    !(forceToplevel [
      {
        aos.sandbox.hostBroker = {
          enable = true;
          credentials = hostCredentialNames "shared";
        };
        aos.sandbox.mountBroker = {
          enable = true;
          credentials = authorityCredentials "mount" // {journalMacKey = "shared-journal-mac-key";};
        };
      }
    ])
    .success;
  invalidNameRejected =
    !(forceToplevel [
      {
        aos.sandbox.hostBroker = {
          enable = true;
          credentials = hostCredentialNames "host" // {nodeId = "../host:node";};
        };
      }
    ])
    .success;
  hostCredentials =
    configured.config.systemd.services.aos-sandbox-hostd.serviceConfig.LoadCredential;
  mountCredentials =
    configured.config.systemd.services.aos-sandbox-mountd.serviceConfig.LoadCredential;
  hostUnit = configured.config.systemd.units."aos-sandbox-hostd.service".text;
  mountUnit = configured.config.systemd.units."aos-sandbox-mountd.service".text;
  observationOnlyUnit = observationOnly.config.systemd.units."aos-sandbox-hostd.service".text;
  credentialLineCount = unit: builtins.length (lib.splitString "LoadCredential=" unit) - 1;
  passed =
    hostCredentials
    == expectedHost "host"
    && mountCredentials == expectedAuthority "mount"
    && credentialLineCount hostUnit == 8
    && credentialLineCount mountUnit == 7
    && credentialLineCount observationOnlyUnit == 7
    && missingRejected
    && partialRejected
    && sharedJournalRejected
    && invalidNameRejected;
in
  if !passed
  then throw "sandbox broker protected-credential module contract failed"
  else
    pkgs.runCommand "sandbox-broker-credential-module-check" {} ''
      mkdir -p $out
      echo PASS > $out/result
    ''
