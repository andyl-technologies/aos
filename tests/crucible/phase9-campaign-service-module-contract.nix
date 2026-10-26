{
  pkgs,
  mkSystem,
  attrPath ? "checks.crucible.phase9.gates.campaignServiceModuleContract",
}: let
  # Each case is evaluated twice: once for its deployable system and once for
  # the module assertions it fails, so a rejected case proves its own reason
  # rather than any unrelated evaluation failure.
  evaluate = campaignConfig: let
    evaluated = mkSystem {
      modules = [
        ../../systems/server.nix
        {aos.services.crucibleCampaign = campaignConfig;}
      ];
      systemName = "campaign-service-contract";
    };
    failedMessages =
      map (assertion: assertion.message)
      (builtins.filter (assertion: !assertion.assertion) evaluated.config.assertions);
  in {
    deployed = builtins.tryEval (
      builtins.deepSeq evaluated.config.system.build.toplevel {
        policyMode = evaluated.config.environment.etc."crucible/campaign-policy.toml".mode or null;
        policyUid = evaluated.config.environment.etc."crucible/campaign-policy.toml".uid or null;
        policyGid = evaluated.config.environment.etc."crucible/campaign-policy.toml".gid or null;
      }
    );
    failures = builtins.tryEval (builtins.deepSeq failedMessages failedMessages);
    identity = builtins.tryEval evaluated.config.aos.services.crucibleCampaign._runtimeIdentity;
  };
  listenMessage = "aos.services.crucibleCampaign.listenAddress must be a numeric loopback address with a valid nonzero TCP port";
  controlMessage = "Crucible campaign runtime values must not contain control characters";
  socketMessage = "aos.services.crucibleCampaign.socketPath must be a normalized file below /run/crucible-campaign";
  stateMessage = "aos.services.crucibleCampaign.stateDirectory must be a normalized path at or below /var/lib/crucible-campaign";
  valid = evaluate {
    enable = true;
    listenAddress = "127.0.0.1:18080";
    socketPath = "/run/crucible-campaign/service.sock";
    stateDirectory = "/var/lib/crucible-campaign";
  };
  invalid = [
    {
      config = {listenAddress = "0.0.0.0:18080";};
      reason = listenMessage;
    }
    {
      config = {listenAddress = "localhost:18080";};
      reason = listenMessage;
    }
    {
      config = {listenAddress = "127.0.0.1:0";};
      reason = listenMessage;
    }
    {
      config = {listenAddress = "127.0.0.1:65536";};
      reason = listenMessage;
    }
    {
      config = {listenAddress = "127.0.0.1:18080\nextra";};
      reason = controlMessage;
    }
    {
      config = {socketPath = "/";};
      reason = socketMessage;
    }
    {
      config = {socketPath = "relative.sock";};
      reason = socketMessage;
    }
    {
      config = {socketPath = "/run/crucible-campaign/../escape.sock";};
      reason = socketMessage;
    }
    {
      config = {socketPath = "/tmp/crucible-campaign.sock";};
      reason = socketMessage;
    }
    {
      config = {stateDirectory = "/";};
      reason = stateMessage;
    }
    {
      config = {stateDirectory = "relative";};
      reason = stateMessage;
    }
    {
      config = {stateDirectory = "/var/lib/crucible-campaign/../escape";};
      reason = stateMessage;
    }
    {
      config = {stateDirectory = "/tmp/crucible-campaign";};
      reason = stateMessage;
    }
  ];
  rejectsForItsReason = case: let
    result = evaluate case.config;
  in
    !result.deployed.success
    && result.failures.success
    && builtins.elem case.reason result.failures.value;
  # Runtime identities of the default configuration, pinned from the module
  # before its service-management migration; release gates bind evidence to
  # these values, so the migration must not change them.
  pinnedIdentities = {
    disabled = "8ddba7ccad9408f69879938000df3a710406da463fb8fb768357416935f494fa";
    enabled = "dda29c1971db127953f12a6da9cded72689159e43234b545bc5ff946c78fbbaf";
  };
  disabledDefault = evaluate {};
  enabledDefault = evaluate {enable = true;};
  identitiesPinned =
    disabledDefault.identity.success
    && disabledDefault.identity.value == pinnedIdentities.disabled
    && enabledDefault.identity.success
    && enabledDefault.identity.value == pinnedIdentities.enabled
    && valid.identity.success
    && valid.identity.value == pinnedIdentities.enabled;
  validContract =
    valid.deployed.success
    && valid.failures.success
    && valid.failures.value == []
    && valid.deployed.value.policyMode == "0444"
    && valid.deployed.value.policyUid == 0
    && valid.deployed.value.policyGid == 0
    && identitiesPinned
    && builtins.all rejectsForItsReason invalid;
in
  if !validContract
  then throw "Crucible campaign service contract accepted an unsafe path or policy file deployment"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-service-module-contract";
      version = "0";
      src = null;
      phases = [
        {
          name = "record-contract";
          script = ''
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            loopback_only=true
            runtime_values_control_free=true
            socket_path_service_owned=true
            state_directory_service_owned=true
            policy_file_regular_root_owned=true
            rejections_bound_to_assertions=true
            runtime_identity_pinned=true
            RESULT
          '';
        }
      ];
    }
