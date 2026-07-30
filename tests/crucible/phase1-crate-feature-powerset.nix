{
  pkgs,
  lib,
}: let
  cratesDir = ../../crates;

  readManifest = package: builtins.fromTOML (builtins.readFile (cratesDir + "/${package}/Cargo.toml"));

  manifestFeatures = package: let
    manifest = readManifest package;
  in
    if manifest ? features
    then manifest.features
    else {};

  assertFeatureSet = package: expected: let
    actual = manifestFeatures package;
    actualNames = lib.sort builtins.lessThan (builtins.attrNames actual);
    expectedNames = lib.sort builtins.lessThan (builtins.attrNames expected);
    nameFailures =
      if actualNames == expectedNames
      then []
      else [
        "${package} feature names drifted: expected [${builtins.concatStringsSep ", " expectedNames}], found [${builtins.concatStringsSep ", " actualNames}]"
      ];
    valueFailures =
      lib.concatMap (
        name:
          if actual.${name} == expected.${name}
          then []
          else [
            "${package} feature `${name}` drifted: expected [${builtins.concatStringsSep ", " expected.${name}}], found [${builtins.concatStringsSep ", " actual.${name}}]"
          ]
      )
      expectedNames;
  in
    nameFailures ++ valueFailures;

  dependencyPackageName = name: value:
    if builtins.isAttrs value && value ? package
    then value.package
    else name;

  isOptionalDependency = value:
    builtins.isAttrs value && value ? optional && value.optional == true;

  featureMembers = features: name:
    if builtins.hasAttr name features
    then features.${name}
    else [];

  defaultFeatureClosure = features: let
    step = seen: queue:
      if queue == []
      then seen
      else let
        feature = builtins.head queue;
        rest = builtins.tail queue;
        members = featureMembers features feature;
        unseen = builtins.filter (member: !(builtins.elem member seen)) members;
      in
        if builtins.elem feature seen
        then step seen rest
        else step (seen ++ [feature]) (rest ++ unseen);
  in
    step [] (featureMembers features "default");

  activatesDependency = feature: dependency: let
    aliases = lib.unique [dependency.name dependency.package];
  in
    builtins.any (
      alias:
        feature
        == alias
        || feature == "dep:${alias}"
        || lib.hasPrefix "${alias}/" feature
        || lib.hasPrefix "${alias}?/" feature
    )
    aliases;

  guestDependencyFailuresFor = manifests: packages:
    lib.concatMap (
      package: let
        manifest = manifests.${package};
        dependencies =
          if manifest ? dependencies
          then manifest.dependencies
          else {};
        features =
          if manifest ? features
          then manifest.features
          else {};
        defaultFeatures = defaultFeatureClosure features;
        guestDeps = builtins.filter (dep: dep.package == "crucible-guest") (
          lib.mapAttrsToList (name: value: {
            inherit name value;
            package = dependencyPackageName name value;
            optional = isOptionalDependency value;
          })
          dependencies
        );
      in
        lib.concatMap (
          dep:
            if !dep.optional
            then [
              "${package} has required dependency `${dep.name}` on crucible-guest"
            ]
            else if builtins.any (feature: activatesDependency feature dep) defaultFeatures
            then [
              "${package} default feature activates optional crucible-guest dependency `${dep.name}`"
            ]
            else []
        )
        guestDeps
    )
    packages;

  corePackages = [
    "crucible-sim"
    "crucible-assert"
    "crucible-shmem"
    "crucible-protocol"
    "crucible-device"
    "crucible"
    "crucible-session"
    "crucible-api"
    "crucible-daemon"
    "crucible-cli"
    "crucible-qemu"
    "crucible-qemu-plugin"
  ];

  readRustTree = path: let
    entries = builtins.readDir path;
    names = builtins.sort builtins.lessThan (builtins.attrNames entries);
    readEntry = name: let
      kind = entries.${name};
      child = path + "/${name}";
    in
      if kind == "directory"
      then readRustTree child
      else if kind == "regular" && lib.hasSuffix ".rs" name
      then builtins.readFile child
      else "";
  in
    builtins.concatStringsSep "\n" (map readEntry names);

  productionTestDoubleFailures =
    lib.concatMap (
      package: let
        manifest = realManifests.${package};
        dependency = (manifest.dependencies or {}).crucible or null;
        features =
          if builtins.isAttrs dependency
          then dependency.features or []
          else [];
      in
        lib.optionals (builtins.elem "test-double" features) [
          "${package} enables crucible/test-double in production dependencies"
        ]
    )
    corePackages;

  unconsumedFeatureFailures =
    lib.concatMap (
      package: let
        features = builtins.attrNames (manifestFeatures package);
        sourcePath = cratesDir + "/${package}/src";
        source =
          if builtins.pathExists sourcePath
          then readRustTree sourcePath
          else "";
      in
        lib.concatMap (
          feature:
            lib.optionals (
              feature
              != "default"
              && !(lib.hasInfix "feature = \"${feature}\"" source)
              && featureMembers (manifestFeatures package) feature == []
            ) [
              "${package} declares feature `${feature}` without a consuming cfg"
            ]
        )
        features
    )
    corePackages;

  realManifests = builtins.listToAttrs (
    map (package: {
      name = package;
      value = readManifest package;
    })
    corePackages
  );

  defaultGuestDependencyFailures =
    guestDependencyFailuresFor realManifests corePackages;

  guestPolicyRegressionFailures = let
    findings = guestDependencyFailuresFor {
      crucible = {
        dependencies.guest-double = {
          package = "crucible-guest";
          optional = true;
        };
        features = {
          default = ["with-guest"];
          with-guest = ["dep:guest-double"];
        };
      };
    } ["crucible"];
  in
    if findings != []
    then []
    else [
      "guest dependency policy regression failed to reject default feature activation"
    ];

  directGuestPolicyRegressionFailures = let
    findings = guestDependencyFailuresFor {
      crucible = {
        dependencies.crucible-guest = {};
        features.default = [];
      };
    } ["crucible"];
  in
    if findings != []
    then []
    else [
      "guest dependency policy regression failed to reject required guest dependency"
    ];

  featureFailures =
    assertFeatureSet "crucible" {
      default = [];
      test-support = [];
      test-double = ["dep:crucible-shmem"];
    }
    ++ assertFeatureSet "crucible-qemu" {
      default = [];
      test-support = ["crucible/test-double"];
    }
    ++ assertFeatureSet "crucible-device" {
      default = [];
    };

  failures =
    featureFailures
    ++ productionTestDoubleFailures
    ++ unconsumedFeatureFailures
    ++ defaultGuestDependencyFailures
    ++ guestPolicyRegressionFailures
    ++ directGuestPolicyRegressionFailures;
in
  if failures != []
  then throw "crucible phase1 crate feature-powerset lint failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-crate-feature-powerset";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.crateFeaturePowerset
            gate=gate:harness-lint
            tasks=T-CRATE-6,T-CRATE-16
            rust_test=crucible-harness::feature_powerset
            RESULT
          '';
        }
      ];
    }
