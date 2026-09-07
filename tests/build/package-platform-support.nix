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
  x86Packages = publicationMatrix.x86_64-darwin;
  armPackages = publicationMatrix.aarch64-darwin;
  x86LinuxPackages = publicationMatrix.x86_64-linux;
  armLinuxPackages = publicationMatrix.aarch64-linux;
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
  assert releaseInventory.schema_version == "aos.release.package-inventory/v1";
  assert releaseInventory.platforms == support.canonicalSystems;
  assert builtins.attrNames publicationMatrix == builtins.sort builtins.lessThan support.canonicalSystems;
  assert x86LinuxPackages == support.targetPackageNames "x86_64-linux" packageNames;
  assert armLinuxPackages == support.targetPackageNames "aarch64-linux" packageNames;
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
