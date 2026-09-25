##! lib/testing/sandbox-network-inspector-guard.nix — closed inspector unit guard checks
{
  lib,
  mkSystem,
  pkgs,
}: let
  inspectorUnitName = "aos-sandbox-network-namespace-inspector@.service";
  inspectorServiceName = "aos-sandbox-network-namespace-inspector@";

  inspectorSystem = overrides:
    mkSystem {
      modules = [
        ../../systems/server.nix
        {aos.sandbox.networkInspector.enable = true;}
        overrides
      ];
      systemName = "sandbox-network-inspector-guard-check";
    };

  source = inspectorSystem {};
  withoutSetId = inspectorSystem {
    systemd.services.${inspectorServiceName}.serviceConfig.RestrictSUIDSGID = lib.mkForce false;
  };
  withoutRingFilter = inspectorSystem {
    systemd.services.${inspectorServiceName}.serviceConfig.SystemCallFilter = lib.mkForce [];
  };
  credentialSources = {
    deploymentContract = "inspector-v1-contract";
    lifecycleWorkerLaunchDigest = "worker-launch-digest";
    inspectorDeploymentVerifierV2 = "inspector-v2-verifier";
    inspectorDeploymentContractV2 = "inspector-v2-contract";
    inspectorLaunchPolicyV3 = "inspector-v3-launch";
  };
  withCredentials = inspectorSystem {
    aos.sandbox.networkInspector.credentials = credentialSources;
  };
  withSharedCredentials = inspectorSystem {
    aos.sandbox.networkInspector.credentials = credentialSources;
    aos.sandbox.networkBroker.credentials = {
      inspectorDeploymentVerifierV2 = credentialSources.inspectorDeploymentVerifierV2;
      inspectorDeploymentContractV2 = credentialSources.inspectorDeploymentContractV2;
      inspectorLaunchPolicyV3 = credentialSources.inspectorLaunchPolicyV3;
    };
  };

  assertionFor = system: message:
    builtins.filter
    (entry: lib.hasInfix message entry.message)
    system.config.assertions;
  holds = system: message: expected: let
    matches = assertionFor system message;
  in
    builtins.length matches == 1
    && (builtins.head matches).assertion == expected;

  unitText = source.config.systemd.units.${inspectorUnitName}.text;
  inspectorSocket = source.config.systemd.sockets.aos-sandbox-network-namespace-inspector;
  inspectorService = source.config.systemd.services.${inspectorServiceName};
  protectedRootsUnit = "aos-sandbox-network-roots.service";
  ringCalls = ["io_uring_setup" "io_uring_enter" "io_uring_register"];
  credentialLoads = [
    "deployment-contract:/run/credentials/@system/inspector-v1-contract"
    "inspector-deployment-contract-v2:/run/credentials/@system/inspector-v2-contract"
    "inspector-deployment-verifier-v2:/run/credentials/@system/inspector-v2-verifier"
    "inspector-launch-policy-v3:/run/credentials/@system/inspector-v3-launch"
    "lifecycle-worker-launch-digest:/run/credentials/@system/worker-launch-digest"
  ];
  passed =
    holds source "remains unavailable until signed V2/V3" false
    && holds source "requires the Network broker and lifecycle worker" false
    && holds withCredentials "must load the same signed V2/V3 credential sources" false
    && holds withSharedCredentials "must load the same signed V2/V3 credential sources" true
    && holds source "requires the protected SELinux Network roots" false
    && holds source "requires the immutable enforcing AOS SELinux policy" false
    && builtins.elem protectedRootsUnit inspectorSocket.requires
    && builtins.elem protectedRootsUnit inspectorSocket.after
    && builtins.elem protectedRootsUnit inspectorService.requires
    && builtins.elem protectedRootsUnit inspectorService.after
    && inspectorService.serviceConfig.LimitNOFILE == 256
    && withCredentials.config.systemd.services.${inspectorServiceName}.serviceConfig.LoadCredential == credentialLoads
    && builtins.all
    (name: holds source "credentials.${name} is required" false)
    (builtins.attrNames withCredentials.config.aos.sandbox.networkInspector.credentials)
    && builtins.all
    (name: holds withCredentials "credentials.${name} is required" true)
    (builtins.attrNames withCredentials.config.aos.sandbox.networkInspector.credentials)
    && holds source "inherited AOS no-set-ID guard" true
    && holds source "reject io_uring creation" true
    && holds withoutSetId "inherited AOS no-set-ID guard" false
    && holds withoutRingFilter "reject io_uring creation" false
    && lib.hasInfix "RestrictSUIDSGID=true\n" unitText
    && builtins.all (name: lib.hasInfix "SystemCallFilter=~${name}\n" unitText) ringCalls;
in
  if !passed
  then throw "sandbox Network inspector guard contract failed"
  else
    pkgs.runCommand "sandbox-network-inspector-guard-check" {} ''
      mkdir -p $out
      echo PASS > $out/result
    ''
