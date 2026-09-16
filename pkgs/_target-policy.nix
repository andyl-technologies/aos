##! Selected package-set platform and publication policy.
##!
##! Package recipes own support facts. This evaluator applies those facts to
##! the platform identities selected by the caller and never enumerates package
##! names, operating systems, CPUs, or publication targets itself.
{
  lib,
  packages,
  releasePlatforms,
}: let
  normalizedReleasePlatforms = builtins.map (
    selected:
      if builtins.isString selected
      then lib.mkPlatform selected
      else selected
  ) releasePlatforms;
  releaseSystems = builtins.map (selected: selected.system) normalizedReleasePlatforms;
  selectedPlatform = system:
    lib.findFirst (
      selected: selected.system == system
    ) (lib.mkPlatform system) normalizedReleasePlatforms;
  packageValue = name:
    packages.${name}
    or (throw "package platform policy: unknown package '${name}'");
  packageSupport = name: let
    package = packageValue name;
  in
    if !builtins.isAttrs package || !(package ? platformSupport)
    then throw "package platform policy: package '${name}' has no native platformSupport declaration"
    else lib.packagePlatform.normalize "package '${name}' platformSupport" package.platformSupport;
  supportsAxis = system: axis: name:
    lib.packagePlatform.supports (selectedPlatform system) (packageSupport name).${axis};
in rec {
  schema = "aos.package-platform-support/v1";
  platforms = releaseSystems;

  supportsTarget = system: name:
    supportsAxis system "host" name;

  targetPackageNames = system: names:
    builtins.filter (supportsTarget system) names;

  publicationDecision = system: name: let
    support = packageSupport name;
    targetSupported = supportsTarget system name;
    publicRole = support.role == "public-package";
  in
    if targetSupported && publicRole
    then {
      state = "eligible";
    }
    else {
      state = "not-applicable";
      rule =
        if !publicRole
        then "package-role/v1"
        else "package-host-constraint/v1";
      reason =
        if !publicRole
        then "Package is not declared as a public package"
        else "Package host constraints do not match the selected release target";
    };

  publicationEligibleNames = system: names:
    builtins.filter (
      name: (publicationDecision system name).state == "eligible"
    ) names;

  publicationEligibleNamesAny = names:
    builtins.filter (
      name:
        builtins.any (
          system: (publicationDecision system name).state == "eligible"
        )
        releaseSystems
    ) names;

  releaseInventory = names: {
    schema_version = "aos.release.package-inventory/v1";
    platforms = releaseSystems;
    packages =
      map (name: {
        inherit name;
        platforms =
          map (platform: {
            inherit platform;
            decision = publicationDecision platform name;
          })
          releaseSystems;
      })
      names;
  };

  releaseDerivations = system: packages: names: let
    eligibleNames = publicationEligibleNames system names;
    outputStorePath = package: output:
      if output == "module"
      then package.module
      else if output == "out"
      then package
      else package.${output};
  in {
    schema_version = "aos.release.derivation-inventory/v1";
    platform = system;
    packages = map (
      name: let
        package = packages.${name};
        selectedOutput = package.outputName or "out";
        publishedOutputs =
          (if selectedOutput == "out"
          then package.outputs or ["out"]
          else [selectedOutput])
          ++ (if package ? module then ["module"] else []);
        normalizeSource = source: let
          sourcePath = toString source;
          storePath = builtins.match "^(/nix/store/[0-9a-z]{32}-[^/]+)(/.*)?$" sourcePath;
        in
          if storePath != null
          then builtins.head storePath
          # Checked-in subdirectories are not store roots during local
          # evaluation. Capture each as an immutable root so the release plan
          # can retain the same source evidence as container publication.
          else if builtins.isPath source
          then
            builtins.path {
              path = source;
              name = builtins.baseNameOf sourcePath;
            }
          else source;
        # Generated packages and language builders declare every source bundle
        # through this passthru contract. Ordinary packages retain their src.
        declaredSources =
          if package ? passthru && package.passthru ? evidenceSources
          then package.passthru.evidenceSources
          else if !(package ? src) || package.src == null
          then []
          else if builtins.isList package.src
          then package.src
          else if toString package.src == ""
          then []
          else [package.src];
        sourcePaths =
          map (
            source:
              builtins.unsafeDiscardStringContext (toString (normalizeSource source))
          )
          (declaredSources
            ++ (if package ? module then [package.module.drvPath] else []));
        contract =
          if !(package ? contract)
          then null
          else {
            document = {
              derivation = builtins.unsafeDiscardStringContext package.contract.document.drvPath;
              store_path = builtins.unsafeDiscardStringContext (toString package.contract.document);
            };
            selectors =
              map (selector: let
                selectedPackageName =
                  if selector.package == "self"
                  then name
                  else selector.package;
                selectedPackage =
                  if builtins.elem selectedPackageName eligibleNames
                  then packages.${selectedPackageName}
                  else throw "package contract for '${name}' selects unpublished package '${selectedPackageName}'";
              in {
                inherit (selector) package output;
                store_path = builtins.unsafeDiscardStringContext (toString (outputStorePath selectedPackage selector.output));
              })
              package.contract.selectors;
          };
      in {
        inherit name contract;
        source_store_paths = builtins.attrNames (builtins.listToAttrs (
          map (source: {
            name = source;
            value = true;
          })
          sourcePaths
        ));
        publication = let
          license = package.meta.license or null;
          licenseExpression =
            if builtins.isList license
            then builtins.concatStringsSep " AND " license
            else license;
          version = package.version or null;
          description = package.meta.description or null;
          maintainers = package.meta.maintainers or [];
        in
          if version == null || description == null || licenseExpression == null || maintainers == []
          then null
          else {
            inherit version description maintainers;
            homepage = package.meta.homepage or null;
            license_expression = licenseExpression;
          };
        derivation = builtins.unsafeDiscardStringContext package.drvPath;
        outputs =
          map (output:
            {
            # A public alias of one non-default derivation output is itself a
            # single-output package root. Normalize that selected root to `out`
            # so package qualification cannot silently exercise a sibling output.
            name =
              if selectedOutput == "out"
              then output
              else "out";
            store_path = builtins.unsafeDiscardStringContext (toString (
              outputStorePath package output
            ));
            }
            // (if output == "module"
            then {derivation = builtins.unsafeDiscardStringContext package.module.drvPath;}
            else {}))
          publishedOutputs;
      }
    ) eligibleNames;
  };


  publicationMatrix = names:
    builtins.listToAttrs (
      map (system: {
        name = system;
        value = targetPackageNames system names;
      }) releaseSystems
    );

  selectTargetPackages = system: selectedPackages: names:
    builtins.listToAttrs (
      map (name: {
        inherit name;
        value = selectedPackages.${name};
      }) (targetPackageNames system names)
    );

  annotate = name: package:
    if !(package ? platformSupport)
    then throw "package platform policy: selected package '${name}' lost its native platformSupport projection"
    else if packageSupport name != package.platformSupport
    then throw "package platform policy: selected package '${name}' changed its native platformSupport projection across package-set splices"
    else package;

  validate = names: let
    missing = builtins.filter (
      name: let package = packageValue name; in
        !builtins.isAttrs package || !(package ? platformSupport)
    ) names;
    invalid = builtins.filter (
      name:
        !(
          builtins.tryEval (
            builtins.deepSeq (packageSupport name) true
          )
        ).success
    ) (builtins.filter (name: !(builtins.elem name missing)) names);
  in
    if missing != []
    then throw "package platform policy: packages without native declarations: ${builtins.toJSON missing}"
    else if invalid != []
    then throw "package platform policy: invalid native declarations: ${builtins.toJSON invalid}"
    else true;
}
