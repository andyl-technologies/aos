##! Shares normal daemon argv with the initial-floor image comparison profile.
{
  config,
  lib,
}: let
  sandbox = config.aos.sandbox;
  controller = sandbox.controller;
  controllerService = sandbox.controllerService;
  storage = sandbox.storageBroker;
  nix = sandbox.nixBroker;
  optionalPath = value:
    if value == null
    then "-"
    else toString value;
  # ExecStart is parsed by PID1, not a shell. Preserve literal dollar signs and
  # specifiers as well as quoting; shell single-quote escaping is not its grammar.
  quote = value:
    if builtins.match "[A-Za-z0-9_./:@=,+-]+" value != null
    then value
    else ''"${builtins.replaceStrings ["\\" "\"" "\n" "\r" "%" "$"] ["\\\\" "\\\"" "\\n" "\\r" "%%" "$$"] value}"'';
  command = argv: {
    inherit argv;
    execStart = builtins.concatStringsSep " " (map quote argv);
  };
in {
  controller = command (
    [
      "${controllerService.package}/bin/aos-sandboxd"
      (toString controller.uid)
      (toString controller.gid)
    ]
    ++ lib.optional controllerService.publicApi.enable "--public-api"
    ++ lib.optional controllerService.publisherIngress.enable "--publisher-ingress"
    ++ lib.optional controllerService.createQ04PolicySubgate.enable "--create-q04-policy-subgate"
    ++ lib.optional controllerService.gitUploadBootstrap.enable "--git-upload-bootstrap"
    ++ lib.optional (controllerService.credentials.gitCoverageEnrollment != null) "--git-upload-coverage"
    ++ lib.optional controllerService.gitReadInspection.enable "--git-read-inspection=${toString sandbox.gitGatewayTransport.uid}:${toString sandbox.gitGatewayTransport.gid}"
    ++ lib.optional controllerService.sourceSuccessorIssuance.enable "--issue-source-successor"
    ++ lib.optional controllerService.operatorRecoveryOnly.enable "--operator-recover-only"
    ++ lib.optional nix.enable "--nix-start-admission"
    ++ lib.optional nix.storageGenerationPrepare.enable "--nix-storage-generation-prepare"
  );

  storage = command (
    [
      "${storage.package}/bin/aos-storaged"
      (toString controller.uid)
      (toString controller.gid)
      (toString storage.identityPoolStart)
      (toString storage.identityPoolSize)
      "${storage.zfsPackage}/sbin/zfs"
      storage.authorityDirectory
      storage.bootstrapDirectory
      (optionalPath storage.resolverPolicyDirectory)
      (toString storage.guestRootTemplate)
      (
        if storage.zfsHoldSigningKey == null
        then "-"
        else "zfs-hold-key-v1"
      )
      (optionalPath storage.executionOutputKey)
    ]
    ++ lib.optional (storage.credentials.gitCoverageEnrollment != null) "--git-upload-exclusive-cohort"
    ++ lib.optional storage.nixGenerationPrepare.enable "--nix-storage-generation-prepare"
  );
}
