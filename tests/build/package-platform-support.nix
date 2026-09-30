# Evaluation contract for package-owned platform declarations.
{pkgs}: let
  support = pkgs.platformSupport;
  packageNames = pkgs.allPackageNames or pkgs.packageNames;
  implicitReleaseInventory = builtins.tryEval (import ../.. {}).releasePackageInventory;
  decisionMatchesRustContract = decision: let
    fields = builtins.attrNames decision;
  in
    if decision.state == "eligible"
    then fields == ["state"]
    else
      decision.state
      == "not-applicable"
      && fields == ["reason" "rule" "state"];
  publicationMatrix = support.publicationMatrix packageNames;
  releaseInventory = support.releaseInventory packageNames;
  releaseDerivations = support.releaseDerivations {
    system = pkgs.stdenv.hostPlatform.system;
    packages = pkgs;
    names = packageNames;
  };
  releaseDerivationRoots = support.releaseDerivationRoots {
    system = pkgs.stdenv.hostPlatform.system;
    packages = pkgs;
    names = packageNames;
  };
  linuxPackages = publicationMatrix.${pkgs.stdenv.hostPlatform.system};
  eligibleOnAnyPlatform = support.publicationEligibleNamesAny packageNames;
  eligibleDecision = support.publicationDecision pkgs.stdenv.hostPlatform.system "aos";
  inapplicableDecision =
    support.publicationDecision pkgs.stdenv.hostPlatform.system "aos-hub-e2e";
  selectionProbe =
    support.selectTargetPackages pkgs.stdenv.hostPlatform.system {
      linux = "included";
      java-native-foundation = "excluded";
    } [
      "java-native-foundation"
      "linux"
    ];
  annotationProbe = support.annotate "rust" pkgs.rust;
  sourceTree = builtins.path {
    path = ../../qualification;
    name = "qualification-source-fixture";
  };
  nestedSource = /. + builtins.unsafeDiscardStringContext (sourceTree + "/modules");
  derivationProbe = support.releaseDerivations {
    system = "x86_64-linux";
    names = ["aos"];
    packages.aos = {
      type = "derivation";
      drvPath = "/nix/store/00000000000000000000000000000000-aos.drv";
      outPath = "/nix/store/00000000000000000000000000000000-aos";
      out = "/nix/store/00000000000000000000000000000000-aos";
      outputs = ["out"];
      src = nestedSource;
      passthru.evidenceSources = [
        nestedSource
        "/nix/store/11111111111111111111111111111111-source/subdirectory"
        "/nix/store/11111111111111111111111111111111-source"
      ];
      pname = "aos";
      version = "1";
      meta = {
        description = "source fixture";
        license = "MIT";
        maintainers = ["AOS test"];
      };
    };
  };
  nativeArtifact = name:
    builtins.derivation {
      inherit name;
      system = pkgs.stdenv.hostPlatform.system;
      builder = "${pkgs.bash}/bin/bash";
      args = ["-c" ''${pkgs.coreutils}/bin/mkdir -p "$out"''];
    };
  deployment = nativeArtifact "platform-probe-deployment";
  documentation = nativeArtifact "platform-probe-documentation";
  qualification = nativeArtifact "platform-probe-qualification";
  moduleSource = builtins.path {
    path = ./fixtures/ability-module-directory;
    name = "platform-probe-module";
  };
  companionPackage =
    (nativeArtifact "platform-probe")
    // {
      pname = "aos";
      version = "1";
      src = nestedSource;
      module = moduleSource;
      out = (nativeArtifact "platform-probe").out // {deploymentArtifact = deployment;};
      deploymentArtifact = deployment;
      documentationArtifact = documentation;
      qualificationArtifact = qualification;
      meta = {
        description = "native companion fixture";
        license = "MIT";
        maintainers = ["AOS test"];
      };
    };
  companionProbe = support.releaseDerivations {
    system = "x86_64-linux";
    names = ["aos"];
    packages.aos = companionPackage;
  };
  probeOnlyQualificationProbe = support.releaseDerivations {
    system = "x86_64-linux";
    names = ["aos"];
    packages.aos = builtins.removeAttrs companionPackage ["module" "documentationArtifact"];
  };
  locator = artifact: {
    derivation = builtins.unsafeDiscardStringContext artifact.drvPath;
    output = "out";
    store_path = builtins.unsafeDiscardStringContext (toString artifact);
  };
  namedDeployment = nativeArtifact "platform-probe-dev-deployment";
  multiOutputPayload = builtins.derivation {
    name = "platform-multi-output-probe";
    system = pkgs.stdenv.hostPlatform.system;
    outputs = ["out" "dev"];
    builder = "${pkgs.bash}/bin/bash";
    args = ["-c" ''${pkgs.coreutils}/bin/mkdir -p "$out" "$dev"''];
  };
  multiOutputPackage =
    companionPackage
    // {
      inherit (multiOutputPayload) drvPath outPath outputs;
      out = multiOutputPayload.out // {deploymentArtifact = deployment;};
      dev = multiOutputPayload.dev // {deploymentArtifact = namedDeployment;};
    };
  multiOutputSelection = {
    system = "x86_64-linux";
    names = ["aos"];
    packages.aos = multiOutputPackage;
  };
  multiOutputInventory = builtins.head (support.releaseDerivations multiOutputSelection).packages;
  multiOutputRoots = map (artifact: builtins.unsafeDiscardStringContext artifact.drvPath) (support.releaseDerivationRoots multiOutputSelection);
  abilityModulePayload = module:
    pkgs.mkDerivation {
      pname = "ability-module-layout-probe";
      version = "1";
      src = null;
      inherit module;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            echo unchanged > "$out/payload"
          '';
        }
      ];
    };
  fileModuleRejected = !(builtins.tryEval (abilityModulePayload ./fixtures/ability-module-file.nix)).success;
  directoryModulePayload = abilityModulePayload ./fixtures/ability-module-directory;
  missingEntryRejected = !(builtins.tryEval (abilityModulePayload ./fixtures)).success;
  directoryModuleArtifact = directoryModulePayload.module;
  sourceRoots = (builtins.head derivationProbe.packages).source_store_paths;
  nestedSourceRoot = builtins.unsafeDiscardStringContext (toString sourceTree);
  pathSet = paths:
    builtins.attrNames (builtins.listToAttrs (map (path: {
        name = path;
        value = true;
      })
      paths));
  plannedDerivationPaths = pathSet (builtins.concatMap (
      package:
        [package.derivation]
        ++ builtins.filter (path: path != null) (map (output: output.derivation or null) package.outputs)
        ++ map (artifact: artifact.derivation) (builtins.filter (artifact: artifact != null) (map (output: output.deployment) package.outputs))
        ++ (
          map (artifact: artifact.derivation)
          (builtins.filter (artifact: artifact != null) [
            package.deployment
            package.module_documentation
            package.qualification
          ])
        )
    )
    releaseDerivations.packages);
  rootDerivationPaths = pathSet (
    map (root: builtins.unsafeDiscardStringContext root.drvPath) releaseDerivationRoots
  );
  releasePackageByName = name:
    builtins.head (builtins.filter (package: package.name == name) releaseDerivations.packages);
  releaseSourcesComplete =
    builtins.all (
      package:
        package.source_store_paths
        != []
        && builtins.all (
          source: builtins.match "^/nix/store/[0-9a-z]{32}-[^/]+$" source != null
        )
        package.source_store_paths
    )
    releaseDerivations.packages;
  packageByName = name:
    builtins.head (builtins.filter (package: package.name == name) releaseInventory.packages);
  decisionFor = name: platform:
    (builtins.head (
      builtins.filter (cell: cell.platform == platform) (packageByName name).platforms
    ))
    .decision;
in
  assert support.validate packageNames;
  assert !(builtins.elem "darwin-runtimes" linuxPackages);
  assert selectionProbe == {linux = "included";};
  assert annotationProbe.platformSupport == pkgs.rust.platformSupport;
  assert sourceRoots
  == builtins.sort builtins.lessThan [
    "/nix/store/11111111111111111111111111111111-source"
    nestedSourceRoot
  ];
  assert (builtins.head companionProbe.packages).outputs
  == [
    {
      derivation = builtins.unsafeDiscardStringContext companionPackage.drvPath;
      name = "out";
      output = "out";
      store_path = builtins.unsafeDiscardStringContext (toString companionPackage);
      deployment = locator deployment;
    }
  ];
  assert (builtins.head companionProbe.packages).deployment == locator deployment;
  assert (builtins.head companionProbe.packages).module_documentation == locator documentation;
  assert (builtins.head companionProbe.packages).qualification == locator qualification;
  assert builtins.elem (toString moduleSource) (builtins.head companionProbe.packages).source_store_paths;
  assert (builtins.head probeOnlyQualificationProbe.packages).module_documentation == null;
  assert (builtins.head probeOnlyQualificationProbe.packages).qualification == locator qualification;
  assert (builtins.head probeOnlyQualificationProbe.packages).deployment == locator deployment;
  assert map (output: output.deployment) multiOutputInventory.outputs
  == [
    (locator deployment)
    (locator namedDeployment)
  ];
  assert builtins.elem deployment.drvPath multiOutputRoots;
  assert builtins.elem namedDeployment.drvPath multiOutputRoots;
  assert fileModuleRejected;
  assert missingEntryRejected;
  assert directoryModulePayload ? deploymentArtifact && directoryModulePayload ? documentationArtifact;
  assert releaseSourcesComplete;
  assert builtins.length (releasePackageByName "aos").source_store_paths >= 2;
  assert builtins.length (releasePackageByName "docker-compose").source_store_paths >= 2;
  assert builtins.length (releasePackageByName "envoy").source_store_paths >= 2;
  assert releaseInventory.schema_version == "aos.release.package-inventory/v1";
  assert rootDerivationPaths == plannedDerivationPaths;
  assert releaseInventory.platforms == support.platforms;
  assert builtins.all (
    package:
      builtins.map (cell: cell.platform) package.platforms
      == support.platforms
      && builtins.all (cell: decisionMatchesRustContract cell.decision) package.platforms
  )
  releaseInventory.packages;
  assert !implicitReleaseInventory.success;
  assert eligibleDecision.state == "eligible";
  assert builtins.attrNames eligibleDecision == ["state"];
  assert inapplicableDecision.state == "not-applicable";
  assert builtins.attrNames inapplicableDecision == ["reason" "rule" "state"];
  assert builtins.stringLength inapplicableDecision.rule > 0;
  assert builtins.stringLength inapplicableDecision.reason > 0;
  assert builtins.attrNames publicationMatrix == builtins.sort builtins.lessThan support.platforms;
  assert linuxPackages == support.targetPackageNames pkgs.stdenv.hostPlatform.system packageNames;
  assert support.publicationEligibleNames pkgs.stdenv.hostPlatform.system packageNames
  == map (package: package.name) releaseDerivations.packages;
  assert builtins.elem "aos-recovery" eligibleOnAnyPlatform;
  assert !(builtins.elem "aos-hub-e2e" eligibleOnAnyPlatform);
  assert (releasePackageByName "dnsutils").outputs
  == [
    {
      derivation = builtins.unsafeDiscardStringContext pkgs.dnsutils.drvPath;
      name = "out";
      output = "dnsutils";
      deployment = locator pkgs.dnsutils.deploymentArtifact;
      store_path = builtins.unsafeDiscardStringContext (toString pkgs.dnsutils);
    }
  ];
  assert (releasePackageByName "getent").outputs
  == [
    {
      derivation = builtins.unsafeDiscardStringContext pkgs.getent.drvPath;
      name = "out";
      output = "getent";
      deployment = locator pkgs.getent.deploymentArtifact;
      store_path = builtins.unsafeDiscardStringContext (toString pkgs.getent);
    }
  ];
  assert builtins.toString pkgs.dnsutils == builtins.toString pkgs.bind.dnsutils;
  assert builtins.toString pkgs.dnsutils != builtins.toString pkgs.bind.out;
  assert builtins.toString pkgs.getent == builtins.toString pkgs.glibc.getent;
  assert builtins.toString pkgs.getent != builtins.toString pkgs.glibc.out;
  assert builtins.all (
    package: builtins.length package.platforms == builtins.length support.platforms
  )
  releaseInventory.packages;
  assert (decisionFor "systemd" "x86_64-linux").state == "eligible";
  assert (decisionFor "darwin-runtimes" "x86_64-linux").state == "not-applicable";
  assert (decisionFor "aos-hub-e2e" "x86_64-linux").state == "not-applicable";
    pkgs.mkDerivation {
      pname = "package-platform-support-check";
      version = "0";
      src = null;
      preferLocalBuild = true;
      allowSubstitutes = false;

      phases = [
        {
          name = "check";
          script = ''
            test -f ${directoryModuleArtifact}/module.nix
            test -f ${directoryModuleArtifact}/private.nix
            test ! -e ${directoryModuleArtifact}/ability-module-directory-sibling.txt
            test "$(find ${directoryModuleArtifact} -mindepth 1 -maxdepth 1 ! -name nix-support -printf '%f\n' | sort)" = "$(printf 'module.nix\nprivate.nix')"
            mkdir -p "$out"
            cat > "$out/result" <<'EOF'
            schema=${support.schema}
            inventory=${toString (builtins.length packageNames)}
            target-packages=${toString (builtins.length linuxPackages)}
            EOF
          '';
        }
      ];
    }
