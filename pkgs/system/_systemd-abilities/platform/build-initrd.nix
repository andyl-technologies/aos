##! Builds the selected systemd initrd from a bounded generic build context.
{
  config,
  initrdAbilityEvaluation,
  lib,
  artifacts,
  systemdArtifact,
}: buildContext: let
  runtimePackages = {
    inherit
      (artifacts)
      bash
      coreutils
      cpio
      cryptsetup
      e2fsprogs
      findutils
      gawk
      gptfdisk
      grep
      iproute2
      jq
      kmod
      less
      util-linux
      zstd
      ;
    systemd = systemdArtifact;
    nix = buildContext.packageSet.nix;
  };
  rendererPackages =
    runtimePackages
    // {
      inherit (buildContext) runCommand writeTextFile;
      inherit (artifacts) sed;
    };
  systemdLib = import ./render.nix {
    inherit lib;
    pkgs = rendererPackages;
  };
  plan = config.system.build.systemdInitrdPlan;
  baseUnits = systemdLib.materializeUnits {
    type = "initrd";
    inherit (plan) etc jobScripts;
  };
  stageConfig =
    if initrdAbilityEvaluation == null
    then throw "the initrd requires its completed native module evaluation"
    else initrdAbilityEvaluation.config;
  bootstrapJSON = builtins.toJSON (import ../bootstrap-services.nix {
    config = stageConfig;
    inherit lib;
    pkgs = artifacts;
  });
  initrdUnits =
    buildContext.runCommand "systemd-initrd-native-bootstrap" {
      inherit bootstrapJSON;
      passAsFile = ["bootstrapJSON"];
    } ''
      ${artifacts.buildPackages.systemd}/bin/aos-service-handler render --output-dir "$out" < "$bootstrapJSONPath"
      # Keep the new output writable for its own metadata finalization.
      cp -a --no-preserve=mode ${baseUnits}/. "$out/"
    '';
  enabledNetworkEffects =
    lib.filterAttrs (_: effect: effect.enable)
    (stageConfig.aos.abilities.network.operations.configure.effects or {});
  networkInputs = lib.mapAttrsToList (name: effect: {
    inherit name;
    file = buildContext.writeTextFile {
      name = "initrd-network-${builtins.hashString "sha256" name}";
      text = builtins.toJSON effect.input;
    };
  })
  enabledNetworkEffects;
  initrdNetworkDir =
    if networkInputs == []
    then null
    else
      buildContext.runCommand "systemd-initrd-native-network" {} ''
        mkdir -p "$out"
        ${lib.concatMapStringsSep "\n" (entry: ''
            rendered="$TMPDIR/network-${builtins.hashString "sha256" entry.name}"
            ${artifacts.buildPackages.systemd}/bin/aos-network-handler render-network --output-dir "$rendered" < ${entry.file}
            for file in "$rendered"/etc/systemd/network/*; do
              test -e "$file" || continue
              filename=$(basename "$file")
              if test -e "$out/$filename"; then
                echo "initrd native network effects collide at $filename" >&2
                exit 1
              fi
              cp -a "$file" "$out/$filename"
            done
          '')
          networkInputs}
      '';

  deploymentBundle = config.system.build.initrdDeploymentBundle;
  initrdRuntimeRoots = lib.unique (map builtins.toString (
    config.aos.boot.initrd.runtimeRoots
    ++ [
      buildContext.packageSet.nix
      lib.packageModuleLibrary
      deploymentBundle
    ]
  ));
  closureInfoFor = lib.build.closureInfo {
    pkgs = buildContext.packageSet.buildPackages;
  };
  registration = closureInfoFor {
    rootPaths = lib.unique (initrdRuntimeRoots ++ [(builtins.toString initrdUnits)]);
    pname = "aos-initrd-native-registration";
  };
  handoff = let
    stageConfig = initrdAbilityEvaluation.config;
    parameters = stageConfig.aos.boot.handoffParameters;
    realization = stageConfig.aos.systemd.initrdHandoffRealization;
  in
    if parameters == null || realization == null
    then throw "systemd initrd requires the typed boot handoff plan and its selected realization"
    else {
      value = parameters;
      inherit realization;
      paths = stageConfig.aos.boot.stageInputPaths;
    };
  selectedKernel =
    if config.aos.kernel.selected == null
    then throw "systemd initrd requires the exact selected kernel projection"
    else config.aos.kernel.selected;
  accountSeed = import ./_identity-bootstrap.nix {
    inherit lib;
    identities = stageConfig.aos.abilities.identity.operations;
    principalReferences =
      lib.unique (builtins.concatLists
        (map (effect: effect.input.accounts) (builtins.attrValues enabledNetworkEffects)));
    accounts = stageConfig.aos.users;
    shells = import ../identity-shells.nix {inherit (runtimePackages) bash util-linux;};
  };
  artifact = import ./_initrd-builder.nix {
    inherit accountSeed;
    inherit lib runtimePackages handoff initrdNetworkDir initrdUnits;
    inherit (buildContext) mkDerivation;
    kernel = selectedKernel;
    kernelModulePackages = config.aos.boot.initrd.modulePackages;
    firmwarePackages = lib.optionals config.aos.kernel.includeFirmware config.aos.boot.initrd.firmwarePackages;
    loadModules = config.aos.boot.initrd.loadModules;
    inherit deploymentBundle registration initrdRuntimeRoots;
    maskedUnits =
      config.boot.initrd.systemd.maskedUnits
      ++ lib.optionals config.aos.security.verity.enable [
        "emergency.target"
        "rescue.target"
      ];
    validateBootIdentity = config.aos.security.verity.enable;
  };
in {
  inherit artifact deploymentBundle;
}
