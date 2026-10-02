##! Checks boot package modules through the native package evaluator.
let
  lib = import ../../lib {system = "x86_64-linux";};
  payload = import ./_fixture-payload.nix;
  artifactLib = import ../../lib/packages/artifacts.nix {};
  artifact = name: {
    inherit name;
    version = "1";
    path = toString (payload name);
    outputs = {
      out = toString (payload name);
      packageRuntime = toString (payload "runtime");
    };
    mainProgram = "handler";
  };
  record = name: source: let
    retained = builtins.path {
      path = source;
      name = "${name}-module";
    };
  in {
    inherit name;
    version = "1";
    configRoot = toString retained;
    module = "${retained}/module.nix";
    artifacts = {
      package =
        (artifact name)
        // {
          outputs = (artifact name).outputs // {module = toString retained;};
        };
      dependencies = builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = artifact name;
      }) ["aos" "nix" "coreutils" "jq" "util-linux" "sbsigntools" "tpm2-tools"]);
    };
  };
  packageModules = [
    (record "service-management" ../../pkgs/system/_service-management)
    (record "aos-boot-storage" ../../pkgs/boot/_aos-boot-storage)
    (record "aos-boot-transaction-storage-provider" ../../pkgs/boot/_aos-boot-transaction-storage-provider)
    (record "aos-boot-preparations" ../../pkgs/boot/_aos-boot-preparations)
    (record "aos-boot-preparation-provider" ../../pkgs/boot/_aos-boot-preparation-provider)
    (record "aos-boot-identity" ../../pkgs/security/_aos-boot-identity)
    (record "aos-verity-root-guard" ../../pkgs/security/_aos-verity-root-guard)
  ];
  evaluateWithControlPlane = controlPlane: stage: zfs: verified:
    lib.evalPackageModules {
      scope = ["boot" stage];
      packageModules = packageModules ++ lib.optional (controlPlane != null) (record "control-plane" ../../pkgs/tools/aos/_abilities/control-plane);
      operatorModules =
        [
          {
            aos.boot = {
              inherit stage;
              substrateServices = {
                enable = true;
                handoffEnabled = true;
                zfsEnabled = zfs;
                zfsPackagePath = toString (payload "zfs");
              };
              storageServices.zfs = {
                enable = zfs;
                packagePath = toString (payload "zfs");
              };
            };
            aos.security = {
              bootIdentityServices.enable = verified;
              verityRootVerification.enable = verified;
            };
            aos.abilities.serviceManagement.operations.realize.handler.program = artifactLib.value (artifact "service-handler");
            aos.abilities.network.operations.configure.handler.program = artifactLib.value (artifact "network-handler");
          }
        ]
        ++ lib.optional (controlPlane != null) {
          options.aos.packageRuntime.configurationEvaluation.nixStoreExecutable = lib.mkOption {
            type = lib.types.str;
            default = "${(artifact "nix").path}/bin/nix-store";
          };
          config.aos.config.unitGraph.enable = controlPlane;
        };
    };
  evaluate = evaluateWithControlPlane null;
  canonicalHost = evaluateWithControlPlane true "host" false true;
  disabledControlPlaneHost = evaluateWithControlPlane false "host" false true;
  hostActivators = evaluation:
    lib.filterAttrs (
      _: service:
        service.enable
        && service.lifecycle != null
        && builtins.any (command: command.executable.arguments != [] && builtins.head command.executable.arguments == "apply-deployment") service.lifecycle.start
    )
    evaluation.config.aos.services;
  initrd = evaluate "initrd" false true;
  host = evaluate "host" false true;
  zfs = evaluate "initrd" true true;
  kernel = evaluate "initrd" false false;
  controller = initrd.config.aos.services."boot-preparations.aos-ability-initrd-controller";
  receiver = host.config.aos.services."boot-preparations.aos-ability-host-receiver";
  bootServices = builtins.filter (service: service.enable) (builtins.attrValues initrd.config.aos.services);
in {
  canonical_host_has_one_activator = assert builtins.attrNames (hostActivators canonicalHost) == ["control-plane.aos-activate"];
  assert canonicalHost.config.aos.boot.hostActivatorService == "control-plane.aos-activate";
  assert canonicalHost.config.aos.services."control-plane.aos-activate".resources.memory_max_bytes.value == 2147483648;
  assert builtins.elem "aos-registry-sync.service" canonicalHost.config.aos.services."control-plane.aos-activate".dependencies.after;
  assert builtins.elem "aos-ability-host-receiver.service" canonicalHost.config.aos.services."control-plane.aos-activate".dependencies.requires;
  assert builtins.elem "local-fs.target" canonicalHost.config.aos.services."control-plane.aos-activate".dependencies.requires;
  assert builtins.elem "multi-user.target" canonicalHost.config.aos.services."control-plane.aos-activate".dependencies.before;
  assert builtins.elem "multi-user.target" canonicalHost.config.aos.services."control-plane.aos-activate".dependencies.required_by; true;
  standalone_host_has_one_activator = assert builtins.attrNames (hostActivators host) == ["boot-preparations.aos-ability-host-controller"];
  assert host.config.aos.boot.hostActivatorService == "boot-preparations.aos-ability-host-controller";
  assert initrd.config.aos.boot.hostActivatorService == null; true;
  disabled_control_plane_preserves_boot_activation = assert builtins.attrNames (hostActivators disabledControlPlaneHost) == ["boot-preparations.aos-ability-host-controller"];
  assert disabledControlPlaneHost.config.aos.boot.hostActivatorService == host.config.aos.boot.hostActivatorService; true;
  host_journal_does_not_claim_unused_esp_storage = let
    hostController = host.config.aos.services."boot-preparations.aos-ability-host-controller";
    stateDirectory = host.config.aos.boot.substrateServices.hostStateDirectory;
  in
    assert !(host.config.aos.abilities.bootTransactionStorage.operations.view.effects ? stage);
    assert !(canonicalHost.config.aos.abilities.bootTransactionStorage.operations.view.effects ? stage);
    assert stateDirectory == "/var/lib/profiles/system/deployment";
    assert builtins.elemAt (builtins.head hostController.lifecycle.start).executable.arguments 4 == stateDirectory;
    assert builtins.elemAt (builtins.head receiver.lifecycle.start).executable.arguments 4 == initrd.config.aos.boot.substrateServices.initrdStateDirectory; true;
  initrd_journal_preserves_firmware_bootstrap_boundary = let
    storage = initrd.config.aos.services."boot-storage.aos-boot-transaction-storage";
  in
    assert storage.enable;
    assert !host.config.aos.services."boot-storage.aos-boot-transaction-storage".enable;
    assert storage.conditions.all
    == [
      {
        kind = "path";
        predicate = "exists";
        path = "/sys/firmware/efi";
        negated = false;
      }
    ];
    assert builtins.elem "sysroot.mount" storage.dependencies.requires;
    assert builtins.elem "aos-boot-transaction-storage.service" controller.dependencies.requires;
    assert initrd.config.aos.abilities.bootTransactionStorage.operations.view.effects.stage.input.path == initrd.config.aos.boot.substrateServices.initrdStateDirectory; true;
  transaction_storage_requires_only_enabled_identity_guard = let
    storage = evaluation: evaluation.config.aos.services."boot-storage.aos-boot-transaction-storage";
    guard = "aos-boot-identity-guard.service";
  in
    assert builtins.elem guard (storage initrd).dependencies.requires;
    assert builtins.elem guard (storage initrd).dependencies.after;
    assert !(builtins.elem guard (storage kernel).dependencies.requires);
    assert !(builtins.elem guard (storage kernel).dependencies.after);
    assert !kernel.config.aos.services."boot-identity.aos-boot-identity-guard".enable; true;
  initrd_bootstrap_has_native_transaction_and_storage = assert controller.lifecycle.start
  == [
    {
      executable = {
        path = "${(artifact "aos-boot-preparations").path}/bin/aos-boot-preparations";
        arguments = [
          "apply-deployment"
          "--input"
          "/lib/aos/initrd/deployment"
          "--state-directory"
          "/run/aos-boot-transaction-storage/aos/initrd-stage-journal"
          "--nix-store"
          "${(artifact "nix").path}/bin/nix-store"
        ];
      };
      ignore_failure = false;
    }
  ];
  assert builtins.elem "aos-boot-transaction-storage.service" controller.dependencies.requires;
  assert initrd.config.aos.abilities.bootTransactionStorage.operations.view.effects.stage.input.path
  == "/run/aos-boot-transaction-storage/aos/initrd-stage-journal"; true;

  bootstrap_service_effects_do_not_start_their_own_controller = assert builtins.all (service: !service.autoStart) bootServices;
  assert builtins.length initrd.deployment.graph.order > 0; true;

  stage_scopes_preserve_host_receipt_verification = assert !host.config.aos.services."boot-preparations.aos-ability-initrd-controller".enable;
  assert receiver.enable;
  assert builtins.head (builtins.head receiver.lifecycle.start).executable.arguments == "verify-deployment";
  assert host.deployment.scope == ["boot" "host"];
  assert initrd.deployment.scope == ["boot" "initrd"]; true;

  zfs_storage_keeps_credentials_and_unlock_ordering = assert zfs.config.aos.services."boot-storage.aos-stage-zfs-credential".enable;
  assert zfs.config.aos.services."boot-storage.aos-zfs-unlock".enable;
  assert builtins.elem "aos-stage-zfs-credential.service"
  zfs.config.aos.services."boot-storage.aos-zfs-unlock".dependencies.requires;
  assert builtins.length zfs.deployment.graph.order > builtins.length initrd.deployment.graph.order; true;

  boot_identity_verification_is_fail_closed = let
    guard = initrd.config.aos.services."boot-identity.aos-boot-identity-guard";
    success = initrd.config.aos.services."boot-identity.aos-boot-identity-success";
  in
    assert guard.enable && success.enable;
    assert !host.config.aos.services."boot-identity.aos-boot-identity-guard".enable;
    assert guard.dependencies.required_by == ["initrd-fs.target"];
    assert guard.dependencies.wants == ["aos-boot-identity-success.service"];
    assert guard.failure_policy.handlers == ["aos-boot-integrity-failure.target"];
    assert guard.failure_policy.dispatch == "isolate-active-goal";
    assert (builtins.head success.lifecycle.start).executable.path == "${(artifact "aos-boot-identity").path}/bin/aos-boot-identity-success"; true;

  verity_verification_precedes_persistent_state = let
    verification = initrd.config.aos.services."verity-root-verification.aos-verity-root-verify";
  in
    assert verification.enable;
    assert !host.config.aos.services."verity-root-verification.aos-verity-root-verify".enable;
    assert verification.dependencies.after == ["aos-boot-identity-guard.service" "aos-systemd-verity-root-setup.service" "aos-ability-initrd-controller.service" "systemd-udev-settle.service"];
    assert verification.dependencies.required_by == ["mount-var.service" "initrd-fs.target"];
    assert verification.failure_policy.handlers == ["aos-boot-integrity-failure.target"];
    assert (builtins.head verification.lifecycle.start).executable.path == "${(artifact "aos-verity-root-guard").path}/bin/aos-verity-root-verify"; true;
}
