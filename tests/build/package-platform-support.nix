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
  configurationBaseProbe = {
    drvPath = "/nix/store/22222222222222222222222222222222-configuration-base.drv";
    outPath = "/nix/store/22222222222222222222222222222222-configuration-base";
    outputName = "out";
  };
  releaseDerivations = support.releaseDerivations {
    system = pkgs.stdenv.hostPlatform.system;
    packages = pkgs;
    names = packageNames;
    configurationBaseLib = configurationBaseProbe;
  };
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
  sourceRoots = (builtins.head derivationProbe.packages).source_store_paths;
  nestedSourceRoot = builtins.unsafeDiscardStringContext (toString (builtins.path {
    path = nestedSource;
    name = builtins.baseNameOf (toString nestedSource);
  }));
  releasePackageByName = name:
    builtins.head (builtins.filter (package: package.name == name) releaseDerivations.packages);
  configuredPackage = releasePackageByName "k3s-worker";
  configuredOutput = name:
    builtins.head (builtins.filter (output: output.name == name) configuredPackage.outputs);
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
  assert releaseSourcesComplete;
  assert configuredPackage.configuration.module_artifact
  == "package/k3s-worker/${pkgs.stdenv.hostPlatform.system}/config";
  assert configuredPackage.configuration.evaluation_base_artifact
  == "package/k3s-worker/${pkgs.stdenv.hostPlatform.system}/configuration-base";
  assert (configuredOutput "out").store_path == builtins.unsafeDiscardStringContext (toString pkgs.k3s-worker);
  assert (configuredOutput "config").derivation == builtins.unsafeDiscardStringContext pkgs.k3s-worker.config.drvPath;
  assert (configuredOutput "config").derivation != configuredPackage.derivation;
  assert (configuredOutput "config").output == "config";
  assert (configuredOutput "configuration-base").derivation == configurationBaseProbe.drvPath;
  assert (configuredOutput "configuration-base").output == "out";
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
