# Evaluation contract for package-owned platform declarations.
{pkgs}: let
  support = pkgs.platformSupport;
  packageNames = pkgs.allPackageNames or pkgs.packageNames;
  releaseSystems = [
    "x86_64-linux"
    "aarch64-linux"
    "x86_64-darwin"
    "aarch64-darwin"
  ];
  implicitReleaseInventory = builtins.tryEval (import ../.. {}).releasePackageInventory;
  selectedRelease = import ../.. {releasePlatforms = releaseSystems;};
  selectedReleaseInventory = selectedRelease.releasePackageInventory;
  decisionMatchesRustContract = decision: let
    fields = builtins.attrNames decision;
  in
    if decision.state == "eligible"
    then fields == ["state"]
    else
      decision.state == "not-applicable"
      && fields == ["reason" "rule" "state"];
  packageMatchesRustContract = package:
    builtins.map (cell: cell.platform) package.platforms == releaseSystems
    && builtins.all (cell: decisionMatchesRustContract cell.decision) package.platforms;

  publicationMatrix = support.publicationMatrix packageNames;
  releaseInventory = support.releaseInventory packageNames;
  releaseDerivations =
    support.releaseDerivations pkgs.stdenv.hostPlatform.system pkgs packageNames;
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
  nestedSource = ../../qualification/modules;
  derivationProbe = support.releaseDerivations "x86_64-linux" {
    aos = {
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
  } ["aos"];
  companionProbe = support.releaseDerivations "x86_64-linux" {
    aos = {
      type = "derivation";
      drvPath = "/nix/store/22222222222222222222222222222222-example.drv";
      outPath = "/nix/store/33333333333333333333333333333333-example";
      out = "/nix/store/33333333333333333333333333333333-example";
      outputs = ["out"];
      src = nestedSource;
      pname = "aos";
      version = "1";
      meta = {
        description = "companion fixture";
        license = "MIT";
        maintainers = ["AOS test"];
      };
      module = {
        type = "derivation";
        outputName = "module";
        drvPath = "/nix/store/44444444444444444444444444444444-example-module.drv";
        outPath = "/nix/store/55555555555555555555555555555555-example-module";
        __toString = value: value.outPath;
      };
      contract = {
        value = {};
        document = {
          type = "derivation";
          drvPath = "/nix/store/66666666666666666666666666666666-example-contract.drv";
          outPath = "/nix/store/77777777777777777777777777777777-example-contract";
          __toString = value: value.outPath;
        };
        selectors = [
          {
            package = "aos";
            output = "module";
          }
          {
            package = "aos";
            output = "out";
          }
        ];
      };
    };
  } ["aos"];
  probeOnlyContractProbe = support.releaseDerivations "x86_64-linux" {
    aos = {
      type = "derivation";
      drvPath = "/nix/store/88888888888888888888888888888888-probe-only.drv";
      outPath = "/nix/store/99999999999999999999999999999999-probe-only";
      out = "/nix/store/99999999999999999999999999999999-probe-only";
      outputs = ["out"];
      src = nestedSource;
      pname = "aos";
      version = "1";
      meta = {
        description = "probe-only fixture";
        license = "MIT";
        maintainers = ["AOS test"];
      };
      contract = {
        value = {};
        document = {
          type = "derivation";
          drvPath = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-probe-contract.drv";
          outPath = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-probe-contract";
          __toString = value: value.outPath;
        };
        selectors = [
          {
            package = "self";
            output = "out";
          }
        ];
      };
    };
  } ["aos"];
  abilityModulePayload = abilities:
    pkgs.mkDerivation {
      pname = "ability-module-layout-probe";
      version = "1";
      src = null;
      inherit abilities;
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
  fileModulePayload = abilityModulePayload ./fixtures/ability-module-file.nix;
  directoryModulePayload = abilityModulePayload ./fixtures/ability-module-directory;
  missingEntryRejected = !(builtins.tryEval (abilityModulePayload ./fixtures)).success;
  fileModuleArtifact = fileModulePayload.module;
  directoryModuleArtifact = directoryModulePayload.module;
  fileProjectionArtifact = fileModulePayload.contract.document;
  directoryProjectionArtifact = directoryModulePayload.contract.document;
  sourceRoots = (builtins.head derivationProbe.packages).source_store_paths;
  nestedSourceRoot = builtins.unsafeDiscardStringContext (toString (builtins.path {
    path = nestedSource;
    name = builtins.baseNameOf (toString nestedSource);
  }));
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
      name = "out";
      store_path = "/nix/store/33333333333333333333333333333333-example";
    }
    {
      name = "module";
      derivation = "/nix/store/44444444444444444444444444444444-example-module.drv";
      store_path = "/nix/store/55555555555555555555555555555555-example-module";
    }
  ];
  assert (builtins.head companionProbe.packages).contract
  == {
    document = {
      derivation = "/nix/store/66666666666666666666666666666666-example-contract.drv";
      store_path = "/nix/store/77777777777777777777777777777777-example-contract";
    };
    selectors = [
      {
        package = "aos";
        output = "module";
        store_path = "/nix/store/55555555555555555555555555555555-example-module";
      }
      {
        package = "aos";
        output = "out";
        store_path = "/nix/store/33333333333333333333333333333333-example";
      }
    ];
  };
  assert (builtins.head probeOnlyContractProbe.packages).contract.selectors
  == [
    {
      package = "self";
      output = "out";
      store_path = "/nix/store/99999999999999999999999999999999-probe-only";
    }
  ];
  assert (builtins.head probeOnlyContractProbe.packages).outputs
  == [
    {
      name = "out";
      store_path = "/nix/store/99999999999999999999999999999999-probe-only";
    }
  ];
  assert fileModulePayload.drvPath == directoryModulePayload.drvPath;
  assert fileModuleArtifact.drvPath != directoryModuleArtifact.drvPath;
  assert missingEntryRejected;
  assert builtins.attrNames fileModulePayload.abilities.interfaces == [];
  assert builtins.attrNames directoryModulePayload.abilities.interfaces == [];
  assert releaseSourcesComplete;
  assert builtins.length (releasePackageByName "aos").source_store_paths >= 2;
  assert builtins.length (releasePackageByName "docker-compose").source_store_paths >= 2;
  assert builtins.length (releasePackageByName "envoy").source_store_paths >= 2;
  assert releaseInventory.schema_version == "aos.release.package-inventory/v1";
  assert releaseInventory.platforms == support.platforms;
  assert !implicitReleaseInventory.success;
  assert selectedReleaseInventory.platforms == releaseSystems;
  assert builtins.all packageMatchesRustContract selectedReleaseInventory.packages;
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
      name = "out";
      store_path = builtins.unsafeDiscardStringContext (toString pkgs.dnsutils);
    }
  ];
  assert (releasePackageByName "getent").outputs
  == [
    {
      name = "out";
      store_path = builtins.unsafeDiscardStringContext (toString pkgs.getent);
    }
  ];
  assert builtins.toString pkgs.dnsutils == builtins.toString pkgs.bind.dnsutils;
  assert builtins.toString pkgs.dnsutils != builtins.toString pkgs.bind.out;
  assert builtins.toString pkgs.getent == builtins.toString pkgs.glibc.getent;
  assert builtins.toString pkgs.getent != builtins.toString pkgs.glibc.out;
  assert builtins.all (
    package: builtins.length package.platforms == builtins.length support.platforms
  ) releaseInventory.packages;
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
            test "$(find ${fileModuleArtifact} -mindepth 1 -maxdepth 1 ! -name nix-support -printf '%f\n')" = module.nix
            test ! -e ${fileModuleArtifact}/ability-module-file-sibling.txt
            test -f ${directoryModuleArtifact}/module.nix
            test -f ${directoryModuleArtifact}/private.nix
            test ! -e ${directoryModuleArtifact}/ability-module-directory-sibling.txt
            test "$(find ${directoryModuleArtifact} -mindepth 1 -maxdepth 1 ! -name nix-support -printf '%f\n' | sort)" = "$(printf 'module.nix\nprivate.nix')"
            cmp ${fileProjectionArtifact} ${directoryProjectionArtifact}
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
