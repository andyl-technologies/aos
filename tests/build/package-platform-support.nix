# Evaluation contract for the fail-closed package target-platform inventory.
{pkgs}: let
  support = import ../../pkgs/_platform-support.nix;
  packageNames = pkgs.allPackageNames or pkgs.packageNames;

  discoverHelpers = directory: prefix: let
    entries = builtins.readDir directory;
  in
    builtins.concatLists (
      map (
        name: let
          entryType = entries.${name};
          relative = "${prefix}${name}";
          startsWithUnderscore = builtins.substring 0 1 name == "_";
          isNix = builtins.match ".*\\.nix" name != null;
        in
          if entryType == "directory"
          then discoverHelpers (directory + "/${name}") "${relative}/"
          else if entryType == "regular" && startsWithUnderscore && isNix
          then [relative]
          else []
      )
      (builtins.attrNames entries)
    );

  discoverPackageExpressions = directory: prefix: let
    entries = builtins.readDir directory;
  in
    builtins.concatLists (
      map (
        name: let
          entryType = entries.${name};
          relative = "${prefix}${name}";
          startsWithUnderscore = builtins.substring 0 1 name == "_";
          isNix = builtins.match ".*\\.nix" name != null;
          nameLength = builtins.stringLength name;
        in
          if entryType == "directory" && !startsWithUnderscore
          then discoverPackageExpressions (directory + "/${name}") "${relative}/"
          else if entryType == "regular" && isNix && !startsWithUnderscore && name != "default.nix"
          then [
            {
              path = relative;
              packageName = builtins.substring 0 (nameLength - 4) name;
            }
          ]
          else []
      )
      (builtins.attrNames entries)
    );

  discoverExcludedResources = directory: prefix: insideExcludedDirectory: let
    entries = builtins.readDir directory;
  in
    builtins.concatLists (
      map (
        name: let
          entryType = entries.${name};
          relative = "${prefix}${name}";
          excluded = insideExcludedDirectory || builtins.substring 0 1 name == "_";
        in
          if entryType == "directory"
          then discoverExcludedResources (directory + "/${name}") "${relative}/" excluded
          else if entryType == "regular" && insideExcludedDirectory
          then [relative]
          else []
      )
      (builtins.attrNames entries)
    );

  helperFiles = discoverHelpers ../../pkgs "";
  packageExpressions = discoverPackageExpressions ../../pkgs "";
  excludedResources = discoverExcludedResources ../../pkgs "" false;
  publicationMatrix = support.publicationMatrix packageNames;
  releaseInventory = support.releaseInventory packageNames;
  releaseDerivations =
    support.releaseDerivations pkgs.stdenv.hostPlatform.system pkgs packageNames;
  x86Packages = publicationMatrix.x86_64-darwin;
  armPackages = publicationMatrix.aarch64-darwin;
  x86LinuxPackages = publicationMatrix.x86_64-linux;
  armLinuxPackages = publicationMatrix.aarch64-linux;
  eligibleOnAnyPlatform = support.publicationEligibleNamesAny packageNames;
  requiredDarwinTools = [
    "aos"
    "bash"
    "bazel"
    "cc"
    "gcc"
    "go"
    "llvm"
    "nodejs"
    "openjdk"
    "python3"
    "rust"
  ];
  rejectedLinuxPackages = [
    "glibc"
    "linux"
    "runc"
    "systemd"
  ];
  requiredPresent =
    builtins.all (
      name: builtins.elem name x86Packages && builtins.elem name armPackages
    )
    requiredDarwinTools;
  rejectedAbsent =
    builtins.all (
      name: !(builtins.elem name x86Packages) && !(builtins.elem name armPackages)
    )
    rejectedLinuxPackages;
  selectionProbe =
    support.selectTargetPackages "aarch64-darwin" {
      linux = "excluded";
      rust = "included";
    } [
      "linux"
      "rust"
    ];
  annotationProbe = support.annotate "rust" {
    meta = {license = "probe";};
  };
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
        aos.platformSupport = {disposition = "target";};
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
        aos.platformSupport = {disposition = "target";};
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
  linuxPackages = support.targetPackageNames "x86_64-linux" packageNames;
  packageByName = name:
    builtins.head (builtins.filter (package: package.name == name) releaseInventory.packages);
  decisionFor = name: platform:
    (builtins.head (
      builtins.filter (cell: cell.platform == platform) (packageByName name).platforms
    ))
    .decision;
in
  assert support.validate packageNames;
  assert support.validateHelpers helperFiles;
  assert support.validateExpressions packageExpressions;
  assert support.validateResources excludedResources;
  assert requiredPresent;
  assert rejectedAbsent;
  assert builtins.elem "darwin-runtimes" x86Packages;
  assert builtins.elem "darwin-runtimes" armPackages;
  assert !(builtins.elem "darwin-runtimes" linuxPackages);
  assert selectionProbe == {rust = "included";};
  assert annotationProbe.meta.license == "probe";
  assert annotationProbe.meta.aos.platformSupport.disposition == "target";
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
  assert releaseInventory.platforms == support.canonicalSystems;
  assert builtins.attrNames publicationMatrix == builtins.sort builtins.lessThan support.canonicalSystems;
  assert x86LinuxPackages == support.targetPackageNames "x86_64-linux" packageNames;
  assert armLinuxPackages == support.targetPackageNames "aarch64-linux" packageNames;
  assert support.publicationEligibleNames "x86_64-linux" packageNames
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
    package: builtins.length package.platforms == 4
  )
  releaseInventory.packages;
  assert (decisionFor "systemd" "x86_64-linux").state == "eligible";
  assert (decisionFor "systemd" "x86_64-linux").blockers == [];
  assert (decisionFor "systemd" "aarch64-darwin").state == "not-applicable";
  assert (decisionFor "darwin-runtimes" "aarch64-darwin").state == "eligible";
  assert (decisionFor "rust" "x86_64-linux").blockers == [];
  assert (decisionFor "rust" "x86_64-darwin").blockers != [];
  assert (decisionFor "darwin-runtimes" "x86_64-linux").state == "not-applicable";
  assert (decisionFor "aos-hub-e2e" "x86_64-linux").state == "not-applicable";
  assert (decisionFor "darling" "aarch64-linux").state == "not-applicable";
  assert (decisionFor "go-1_4" "aarch64-linux").state == "not-applicable";
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
            helpers=${toString (builtins.length helperFiles)}
            expressions=${toString (builtins.length packageExpressions)}
            resources=${toString (builtins.length excludedResources)}
            x86_64-darwin=${toString (builtins.length x86Packages)}
            aarch64-darwin=${toString (builtins.length armPackages)}
            EOF
          '';
        }
      ];
    }
