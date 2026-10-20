##! Checks scoped early provisioning against the actual retained package modules.
{
  pkgs,
  lib,
}: let
  evaluate = checkDefinitions: operatorModules:
    lib.evalPackageModules {
      inherit checkDefinitions operatorModules;
      packages = [pkgs.aos-storage-provisioning-provider];
      scope = ["test" "provisioning-projection"];
    };
  project = modules:
    ((evaluate false modules).extendModules {
      checkDefinitionPaths = [["aos" "provisioning"]];
    }).config.aos.provisioning.storage;
  rejects = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
  valid = {
    aos.provisioning.storage = {
      partitions = {
        var.sizeMin = "8G";
        member-a.sizeMin = "512M";
        member-b.sizeMin = "512M";
      };
      arrays.data = {
        level = "raid1";
        members = ["member-a" "member-b"];
        format = "xfs";
        encryption = "tpm2";
      };
    };
  };
  laterPackage = {
    aos.futurePackage.settings = throw "early storage projection forced a later package option";
  };
  selected = project [valid laterPackage];
  packageModules = (import ../../lib/build/package-modules.nix {}).closure [pkgs.aos-storage-provisioning-provider];
  # Only physical import locations change; resolver-supplied source and payload
  # identities remain the canonical package records.
  packageImportRoots = builtins.listToAttrs (map (record: {
      name = builtins.unsafeDiscardStringContext record.configRoot;
      value = builtins.path {
        path = record.configRoot;
        name = "${record.name}-provisioning-source-view";
      };
    })
    packageModules);
  copiedSources = lib.evalPackageModules {
    inherit packageModules packageImportRoots;
    packages = [pkgs.aos-storage-provisioning-provider];
    checkDefinitions = false;
    operatorModules = [valid laterPackage];
    scope = ["test" "provisioning-copied-source-view"];
  };
  copiedProjection = copiedSources.extendModules {
    checkDefinitionPaths = [["aos" "provisioning"]];
  };
  conditional = project [
    valid
    {
      config = lib.mkIf false {
        aos.provisioning.typo = 1;
        aos.provisioning.storage.partitions.var.sizeMin = 42;
      };
    }
  ];
  merged = project [
    {
      config = lib.mkMerge [
        {aos.provisioning.storage.partitions.var.sizeMin = lib.mkDefault "6G";}
        (lib.mkIf true {aos.provisioning.storage.partitions.var.sizeMin = lib.mkForce "12G";})
        {aos.futurePackage.enabled = true;}
      ];
    }
  ];
in {
  actualDeclarationAndDefaults = assert selected.partitions.var.sizeMin == "8G";
  assert selected.partitions.swap.format == "swap";
  assert selected.arrays.data.members == ["member-a" "member-b"];
  assert selected.arrays.data.encryption == "tpm2"; true;
  copiedSourceViewsRetainTypedStorage = assert builtins.all (record:
    builtins.toString packageImportRoots.${builtins.unsafeDiscardStringContext record.configRoot} != record.configRoot)
  packageModules;
  assert copiedSources.documentation.packages == (evaluate false [valid laterPackage]).documentation.packages;
  assert builtins.toJSON copiedProjection.config.aos.provisioning.storage == builtins.toJSON selected; true;
  copiedSourceViewsRequireAdmission = assert rejects
  (copiedSources.extendModules {
    # Models the old extension bug, which silently dropped the source-view map.
    packageImportRoots = {};
    checkDefinitionPaths = [["aos" "provisioning"]];
  }).config.aos.provisioning.storage; true;
  provisioningTypoRejected = assert rejects (project [valid {aos.provisioning.stroage = {};}]); true;
  storageTypoRejected = assert rejects (project [valid {aos.provisioning.storage.partitons = {};}]); true;
  malformedAncestorRejected = assert rejects (project [{aos.provisioning = 42;}]); true;
  malformedStorageTypeRejected = assert rejects (project [valid {aos.provisioning.storage.partitions.var.sizeMin = lib.mkForce 42;}]); true;
  unknownPartitionFieldRejected = assert rejects (project [valid {aos.provisioning.storage.partitions.var.sizeMni = "8G";}]); true;
  unknownArrayFieldRejected = assert rejects (project [valid {aos.provisioning.storage.arrays.data.memberz = [];}]); true;
  fullHostStillRejectsForeignOptions = assert rejects (evaluate true [valid {aos.futurePackage.enabled = true;}]).deployment.graph; true;
  authoredStrictCannotDisableProjection = assert rejects (project [
    valid
    {
      _module.strict = lib.mkForce false;
      aos.provisioning.stroage = {};
    }
  ]); true;
  authoredFreeformCannotAcceptProvisioningTypo = assert rejects (project [
    valid
    {
      _module.freeformType = lib.types.attrs;
      aos.provisioning.stroage = {};
    }
  ]); true;
  unrelatedFreeformRemainsAvailable = assert (project [
    valid
    {
      _module.freeformType = lib.types.attrs;
      aos.futurePackage.enabled = true;
    }
  ]).partitions.var.sizeMin
  == "8G"; true;
  trustedPathsSurviveExtension = assert rejects
  (((evaluate false [valid]).extendModules {
      checkDefinitionPaths = [["aos" "provisioning"]];
    }).extendModules {
      modules = [{aos.provisioning.stroage = {};}];
    }).config.aos.provisioning.storage; true;
  falseGuardsRemainInactive = assert conditional.partitions.var.sizeMin == "8G"; true;
  mergeAndPrioritiesRemainTyped = assert merged.partitions.var.sizeMin == "12G";
  assert merged.partitions.swap.sizeMin == "2G"; true;
}
