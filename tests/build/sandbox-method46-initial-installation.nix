# Evaluates actual installed initializer composition without building policy.
# These public DATA pins exercise definitions only; no Source, signature,
# native Parent06 programme fit or TPM execution is established by this check.
{
  lib,
  pkgs,
  systems,
}: let
  purposes = ["controller" "storage"];
  system = import ../fleet/_sandbox-method46-initial-system.nix {
    inherit lib pkgs systems;
    approvalPublicKeys = {
      controller = lib.genList (_: 11) 32;
      storage = lib.genList (_: 12) 32;
    };
  };
  cfg = system.config;
  parent = cfg.aos.sandbox.resourceBank.parentEnclosure;
  failedAssertions = builtins.filter (check: !check.assertion) cfg.assertions;
  rejects = message: selected:
    builtins.any (check: check.message == message && !check.assertion) selected.config.assertions;
  changed = module: system.extendModules {modules = [module];};
  manualMessage = "Manual initial-floor units must remain unbootstrapped, argument-free and bound to their exact original delivery; normal startup cannot initialize.";
  credentialMessage = purpose: "Manual ${purpose} floor initialization requires its independent public approval pin and the actual normal owners' complete external public credential sources.";
  parentMessage = purpose: "Manual ${purpose} floor initialization requires explicit, separate Parent06 receiving and sender subdivisions.";
  unitName = purpose: "aos-sandbox-${purpose}-floor-initialize";
  allocation = purpose:
    if purpose == "controller"
    then "method46ControllerInitial"
    else "method46StorageInitial";
  normal = purpose:
    if purpose == "controller"
    then "controllerService"
    else "storageBroker";
  rootSigningSource = "/run/credentials/@system/qualification-root-noapply-signing";
  rootPublicSource = "/run/credentials/@system/qualification-root-noapply-public";
  rootCredentials = cfg.systemd.services.aos-sandbox-policy-authorityd.serviceConfig.LoadCredential;
  hostCredentials = cfg.systemd.services.aos-sandbox-hostd.serviceConfig.LoadCredential;
  recoveryCredentials = cfg.systemd.services.aos-sandbox-policy-cache-recovery.serviceConfig.LoadCredential or [];
  hasSource = source: entries: builtins.any (lib.hasSuffix ":${source}") entries;

  refusesIncomplete = purpose: let
    name = unitName purpose;
    missingApproval = changed {
      aos.sandbox.method46InitialFloors.${purpose}.approvalPublicKeyCredential = lib.mkForce null;
    };
    missingAuth = changed {
      aos.sandbox.${normal purpose}.method46TpmFloor.indexAuthCredential = lib.mkForce null;
    };
    missingSender = changed {
      aos.sandbox.resourceBank.parentEnclosure."${allocation purpose}Sender" = lib.mkForce null;
    };
    automatic = changed {systemd.services.${name}.wantedBy = ["multi-user.target"];};
  in
    rejects (credentialMessage purpose) missingApproval
    && rejects "method46TpmFloor requires distinct external public/auth credentials in required mode, or neither in permanently closed legacy mode" missingAuth
    && rejects (parentMessage purpose) missingSender
    && rejects manualMessage automatic;

  projection = lib.genAttrs purposes (purpose: let
    service = cfg.systemd.services.${unitName purpose};
    settings = service.serviceConfig;
    budget = parent."${allocation purpose}Receiving";
  in
    assert service.wantedBy == [] && service.requiredBy == [];
    assert settings.MemoryMax == budget.memory-bytes;
    assert settings.TasksMax == budget.pids;
    assert settings.CPUQuota == "${toString (budget.cpu-micros-per-period / 1000)}%";
    assert settings.LimitNOFILE == parent.fixedOpenFilesPerProcess;
    assert builtins.length settings.LoadCredential == 29;
    assert builtins.elem "method46-normal-root-noapply-public-key-v2:${rootPublicSource}" settings.LoadCredential;
    assert !(hasSource rootSigningSource settings.LoadCredential); {
      inherit (settings) MemoryMax TasksMax CPUQuota LimitNOFILE SELinuxContext;
      credentialCount = builtins.length settings.LoadCredential;
    });
  validation = assert failedAssertions
  == []
  || throw (builtins.concatStringsSep "\n" (map (check: check.message) failedAssertions));
  assert cfg.aos.security.selinux._productionPolicy.passthru.method46InitialPurposes == purposes;
  assert cfg.aos.sandbox.resourceBank.policy.capacity.tmpfs-bytes == 1073741824;
  assert cfg.systemd.services.aos-sandboxd.wantedBy == [];
  assert builtins.elem "root-noapply-floor-signing:${rootSigningSource}" rootCredentials;
  assert builtins.elem "root-noapply-floor-public:${rootPublicSource}" rootCredentials;
  assert builtins.elem "root-noapply-floor-public:${rootPublicSource}" hostCredentials;
  assert !(hasSource rootSigningSource hostCredentials);
  assert !(hasSource rootSigningSource recoveryCredentials);
  assert !(hasSource rootPublicSource recoveryCredentials);
  assert builtins.all refusesIncomplete purposes;
    builtins.deepSeq projection true;
in
  assert validation;
    pkgs.runCommand "sandbox-method46-initial-installation-check" {
      projectionJson = builtins.toJSON projection;
    } ''
      mkdir -p "$out"
      printf '%s\n' "$projectionJson" > "$out/units.json"
      printf '%s\n' PASS > "$out/result"
    ''
