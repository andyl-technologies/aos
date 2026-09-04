##! mkUpstream — validated AOS-local upstream package contract
{
  lib,
  fetchurl,
  platform,
}: let
  sortedNames = value: builtins.sort builtins.lessThan (builtins.attrNames value);

  assertFields = label: required: optional: value: let
    actual = sortedNames value;
    allowed = builtins.sort builtins.lessThan (required ++ optional);
    unknown = builtins.filter (name: !(builtins.elem name allowed)) actual;
    missing = builtins.filter (name: !(builtins.hasAttr name value)) required;
  in
    if !builtins.isAttrs value
    then throw "mkUpstream: ${label} must be an attribute set"
    else if unknown != []
    then throw "mkUpstream: ${label} has unknown fields: ${builtins.toJSON unknown}"
    else if missing != []
    then throw "mkUpstream: ${label} lacks required fields: ${builtins.toJSON missing}"
    else value;

  requireString = label: value:
    if builtins.isString value && value != ""
    then value
    else throw "mkUpstream: ${label} must be a non-empty string";

  requireEnum = label: choices: value:
    if builtins.elem value choices
    then value
    else throw "mkUpstream: ${label} must be one of ${builtins.toJSON choices}";

  requireSortedStrings = label: values:
    if
      builtins.isList values
      && builtins.all (value: builtins.isString value && value != "") values
      && values == builtins.sort builtins.lessThan (lib.unique values)
    then values
    else throw "mkUpstream: ${label} must contain unique sorted non-empty strings";

  # Candidate-controlled values remain inside one path segment. The initial
  # contract accepts the RFC 3986 unreserved alphabet plus `+`; later adapters
  # may add a typed percent encoder without allowing origin or path injection.
  requireSafeSegmentText = label: value:
    if
      builtins.isString value
      && value != ""
      && builtins.match "[-A-Za-z0-9._~+]+" value != null
    then value
    else throw "mkUpstream: ${label} contains unsafe URL path text";

  fieldValue = components: reference: let
    checked = assertFields "componentField" ["component" "field"] [] reference;
    componentName = requireString "componentField.component" checked.component;
    component =
      if builtins.hasAttr componentName components
      then components.${componentName}
      else throw "mkUpstream: URL template references unknown component '${componentName}'";
    field = requireEnum "componentField.field" ["comparisonVersion" "upstreamId"] checked.field;
  in
    requireSafeSegmentText "componentField value" component.current.${field};

  normalizePart = components: part:
    if part ? literal
    then let
      checked = assertFields "URL literal part" ["literal"] [] part;
    in {
      kind = "literal";
      value = requireSafeSegmentText "URL literal" checked.literal;
    }
    else if part ? componentField
    then let
      checked = assertFields "URL component part" ["componentField"] [] part;
      reference = assertFields "componentField" ["component" "field"] [] checked.componentField;
    in {
      kind = "component-field";
      component = requireString "componentField.component" reference.component;
      field = requireEnum "componentField.field" ["comparisonVersion" "upstreamId"] reference.field;
    }
    else throw "mkUpstream: URL part must contain literal or componentField";

  renderPart = components: part:
    if part ? literal
    then requireSafeSegmentText "URL literal" part.literal
    else if part ? componentField
    then fieldValue components part.componentField
    else throw "mkUpstream: URL part must contain literal or componentField";

  normalizeSegment = components: segment:
    if builtins.isString segment
    then {
      kind = "literal";
      value = requireSafeSegmentText "URL path segment" segment;
    }
    else let
      checked = assertFields "URL path segment" ["parts"] [] segment;
    in {
      kind = "parts";
      parts = builtins.map (normalizePart components) checked.parts;
    };

  renderSegment = components: segment:
    if builtins.isString segment
    then requireSafeSegmentText "URL path segment" segment
    else let
      checked = assertFields "URL path segment" ["parts"] [] segment;
    in
      builtins.concatStringsSep "" (builtins.map (renderPart components) checked.parts);

  normalizeTemplate = components: template: let
    checked = assertFields "URL template" ["scheme" "authority" "path"] [] template;
    scheme = requireEnum "URL scheme" ["https"] checked.scheme;
    authority = requireString "URL authority" checked.authority;
    authorityValid =
      builtins.match "[A-Za-z0-9.-]+" authority
      != null
      && builtins.match ".*\\.\\..*" authority == null;
  in
    if !authorityValid
    then throw "mkUpstream: URL authority must be a fixed ASCII hostname"
    else {
      inherit scheme authority;
      path = builtins.map (normalizeSegment components) checked.path;
    };

  renderTemplate = components: template: let
    checked = assertFields "URL template" ["scheme" "authority" "path"] [] template;
    normalized = normalizeTemplate components checked;
    path = builtins.concatStringsSep "/" (builtins.map (renderSegment components) checked.path);
  in "${normalized.scheme}://${normalized.authority}/${path}";

  normalizeProvider = provider: let
    providerName = requireEnum "discovery provider" ["github-tags"] provider.provider;
    checked = assertFields "primary discovery" ["provider" "repository"] ["tagPrefix"] provider;
  in {
    provider = providerName;
    repository = requireString "primary repository" checked.repository;
    tagPrefix = checked.tagPrefix or "";
  };

  normalizeAdvisors = advisors:
    if advisors == {}
    then []
    else let
      checked = assertFields "discovery advisors" [] ["repology"] advisors;
    in
      lib.optional (checked ? repology) {
        provider = "repology";
        project =
          requireString "Repology project"
          (
            assertFields "Repology advisor" ["project"] [] checked.repology
          )
          .project;
      };

  normalizeReleasePolicy = policy: let
    checked = assertFields "releasePolicy" ["strategy" "versionScheme"] ["series" "allowPrerelease" "minimumAgeDays"] policy;
    series =
      if checked ? series
      then assertFields "releasePolicy.series" ["major"] [] checked.series
      else null;
  in {
    strategy = requireEnum "release strategy" ["latest-in-series" "channel" "vcs-lineage"] checked.strategy;
    versionScheme = requireEnum "version scheme" ["semver" "numeric" "provider"] checked.versionScheme;
    seriesMajor =
      if series != null && builtins.isInt series.major && series.major >= 0
      then series.major
      else if series == null
      then null
      else throw "mkUpstream: releasePolicy.series.major must be a non-negative integer";
    allowPrerelease = checked.allowPrerelease or false;
    minimumAgeDays = checked.minimumAgeDays or 0;
  };

  normalizeSource = components: slotName: source: let
    checked = assertFields "source '${slotName}'" ["fetcher" "urlTemplates" "hash" "hashMode" "allowedRedirectHosts"] [] source;
    templates = builtins.map (normalizeTemplate components) checked.urlTemplates;
    urls = builtins.map (renderTemplate components) checked.urlTemplates;
    hash = requireString "source hash" checked.hash;
    derivation = fetchurl {inherit urls hash;};
  in {
    metadata = {
      fetcher = requireEnum "source fetcher" ["fetchurl"] checked.fetcher;
      derivation = derivation.drvPath;
      urlTemplates = templates;
      inherit hash;
      hashMode = requireEnum "source hashMode" ["flat" "recursive"] checked.hashMode;
      allowedRedirectHosts = requireSortedStrings "allowedRedirectHosts" checked.allowedRedirectHosts;
    };
    inherit derivation;
  };

  normalizeComponent = components: componentName: component: let
    checked = assertFields "component '${componentName}'" ["current" "discovery" "releasePolicy" "sources"] [] component;
    current = assertFields "component '${componentName}'.current" ["upstreamId" "comparisonVersion"] [] checked.current;
    discovery = assertFields "component '${componentName}'.discovery" ["primary"] ["advisors"] checked.discovery;
    sources = builtins.mapAttrs (normalizeSource components) checked.sources;
  in {
    metadata = {
      current = {
        upstreamId = requireString "current upstreamId" current.upstreamId;
        comparisonVersion = requireString "current comparisonVersion" current.comparisonVersion;
      };
      primary = normalizeProvider discovery.primary;
      advisors = normalizeAdvisors (discovery.advisors or {});
      releasePolicy = normalizeReleasePolicy checked.releasePolicy;
      sources = builtins.mapAttrs (_: value: value.metadata) sources;
    };
    sourceDerivations = builtins.mapAttrs (_: value: value.derivation) sources;
  };

  requireRelativePath = label: value:
    if
      builtins.isString value
      && value != ""
      && builtins.match "/.*" value == null
      && builtins.match ".*/(\\.|\\.\\.)(/.*)?" value == null
    then value
    else throw "mkUpstream: ${label} must be a normalized relative path";

  normalizeArtifactInput = components: artifacts: input: let
    checked = assertFields "artifact input" ["kind"] ["component" "slot" "artifact"] input;
    kind = requireEnum "artifact input kind" ["source" "artifact"] checked.kind;
  in
    if kind == "source"
    then let
      component = requireString "artifact input component" checked.component;
      slot = requireString "artifact input source slot" checked.slot;
    in
      if !(builtins.hasAttr component components) || !(builtins.hasAttr slot components.${component}.sources)
      then throw "mkUpstream: artifact input references an unknown source slot"
      else {inherit kind component slot;}
    else let
      artifact = requireString "artifact input artifact" checked.artifact;
    in
      if !(builtins.hasAttr artifact artifacts)
      then throw "mkUpstream: artifact input references an unknown artifact slot"
      else {inherit kind artifact;};

  normalizeMaterializer = materializer: let
    kind = requireEnum "artifact materializer kind" ["cargo-deps" "cargo-vendor" "go-modules" "npm-deps" "bazel-deps"] materializer.kind;
    expectedBuilder =
      {
        cargo-deps = "fetchCargoDeps/v1";
        cargo-vendor = "fetchCargoVendor/v1";
        go-modules = "fetchGoModules/v1";
        npm-deps = "fetchNpmDeps/v1";
        bazel-deps = "fetchBazelDeps/v1";
      }.${
        kind
      };
    builder = requireString "artifact builder identity" materializer.builder;
    common = {
      inherit kind;
      sourceRoot = requireRelativePath "artifact sourceRoot" materializer.sourceRoot;
      inherit builder;
    };
  in
    if builder != expectedBuilder
    then throw "mkUpstream: ${kind} requires builder identity '${expectedBuilder}'"
    else if builtins.elem kind ["cargo-deps" "cargo-vendor"]
    then let
      checked = assertFields "${kind} materializer" ["kind" "sourceRoot" "patches" "builder"] [] materializer;
    in
      common // {patches = builtins.map (requireRelativePath "artifact patch") checked.patches;}
    else if kind == "go-modules"
    then let
      checked = assertFields "go-modules materializer" ["kind" "sourceRoot" "moduleRoots" "builder"] [] materializer;
    in
      common // {moduleRoots = requireSortedStrings "Go moduleRoots" checked.moduleRoots;}
    else if kind == "npm-deps"
    then let
      checked = assertFields "npm-deps materializer" ["kind" "sourceRoot" "manifest" "lockfile" "lifecycleScripts" "builder"] [] materializer;
    in
      if checked.lifecycleScripts != false
      then throw "mkUpstream: npm dependency acquisition cannot run lifecycle scripts"
      else
        common
        // {
          manifest = requireRelativePath "npm manifest" checked.manifest;
          lockfile = requireRelativePath "npm lockfile" checked.lockfile;
          lifecycleScripts = false;
        }
    else let
      checked = assertFields "bazel-deps materializer" ["kind" "sourceRoot" "target" "flags" "patches" "builder"] [] materializer;
    in
      common
      // {
        target = requireString "Bazel target" checked.target;
        flags = builtins.map (requireString "Bazel flag") checked.flags;
        patches = builtins.map (requireRelativePath "artifact patch") checked.patches;
      };

  normalizeArtifactOutput = output: let
    checked = assertFields "artifact output" ["path" "format" "expectedPreimage" "transformation"] [] output;
  in {
    path = requireRelativePath "artifact output path" checked.path;
    format = requireEnum "artifact output format" ["json" "toml"] checked.format;
    expectedPreimage = requireString "artifact output expectedPreimage" checked.expectedPreimage;
    transformation = requireEnum "artifact output transformation" ["cargo-lock" "npm-lock"] checked.transformation;
  };

  normalizeArtifact = components: artifacts: artifactName: artifact: let
    checked = assertFields "artifact '${artifactName}'" ["inputs" "hash" "materializer"] ["outputs"] artifact;
    inputs = builtins.map (normalizeArtifactInput components artifacts) checked.inputs;
  in {
    inherit inputs;
    hash = requireString "artifact hash" checked.hash;
    materializer = normalizeMaterializer checked.materializer;
    outputs = builtins.map normalizeArtifactOutput (checked.outputs or []);
  };
in
  spec: let
    checked = assertFields "contract" ["schema" "unitId" "family" "stream" "owner" "classification" "package" "components" "policy"] ["artifacts" "cohort"] spec;
    schema = requireEnum "schema" ["aos.package-update/v1"] checked.schema;
    classification = requireEnum "classification" ["automatic" "assisted"] checked.classification;
    package = assertFields "package" ["currentVersion" "versionProjection"] [] checked.package;
    projection = assertFields "package.versionProjection" ["kind" "component" "field"] [] package.versionProjection;
    policy = assertFields "policy" ["lifecycle" "riskFloor"] ["repairScope" "successorUnit"] checked.policy;
    normalizedComponents = builtins.mapAttrs (normalizeComponent checked.components) checked.components;
    componentMetadata = builtins.mapAttrs (_: value: value.metadata) normalizedComponents;
    normalizedArtifacts = builtins.mapAttrs (normalizeArtifact componentMetadata (checked.artifacts or {})) (checked.artifacts or {});
    projectedComponent = requireString "versionProjection.component" projection.component;
    projectedField = requireEnum "versionProjection.field" ["comparisonVersion" "upstreamId"] projection.field;
    projectedVersion =
      if projection.kind != "component-field"
      then throw "mkUpstream: unsupported package version projection"
      else if !(builtins.hasAttr projectedComponent checked.components)
      then throw "mkUpstream: package projection references unknown component '${projectedComponent}'"
      else checked.components.${projectedComponent}.current.${projectedField};
    currentVersion = requireString "package.currentVersion" package.currentVersion;
    normalized = {
      inherit schema classification;
      unitId = requireString "unitId" checked.unitId;
      family = requireString "family" checked.family;
      stream = requireString "stream" checked.stream;
      owner = requireString "owner" checked.owner;
      cohort =
        if checked ? cohort
        then requireString "cohort" checked.cohort
        else null;
      package = {
        inherit currentVersion;
        versionProjection = {
          kind = "component-field";
          component = projectedComponent;
          field = projectedField;
        };
      };
      components = componentMetadata;
      artifacts = normalizedArtifacts;
      policy =
        {
          lifecycle = requireEnum "policy.lifecycle" ["supported" "security-only" "frozen" "retiring"] policy.lifecycle;
          riskFloor = requireEnum "policy.riskFloor" ["low" "normal" "high" "critical"] policy.riskFloor;
          repairScope = requireSortedStrings "policy.repairScope" (policy.repairScope or []);
        }
        // lib.optionalAttrs (policy ? successorUnit) {
          successorUnit = requireString "policy.successorUnit" policy.successorUnit;
        };
    };
  in
    if projectedVersion != currentVersion
    then throw "mkUpstream: package.currentVersion disagrees with its version projection"
    else {
      version = currentVersion;
      components = builtins.mapAttrs (_: value: {sources = value.sourceDerivations;}) normalizedComponents;
      artifacts = builtins.mapAttrs (_: value: {inherit (value) hash;}) normalizedArtifacts;
      forPackage = memberSpec: let
        memberChecked = assertFields "forPackage" ["member"] ["artifacts"] memberSpec;
        member = requireString "member" memberChecked.member;
        artifactDerivations = memberChecked.artifacts or {};
        expectedArtifacts = sortedNames normalizedArtifacts;
        actualArtifacts = sortedNames artifactDerivations;
        artifacts =
          if expectedArtifacts != actualArtifacts
          then throw "mkUpstream: forPackage artifacts must exactly match declared artifact slots"
          else
            builtins.mapAttrs (
              name: value: let
                actual =
                  artifactDerivations.${name}.passthru.aos.fixedOutput
                    or (throw "mkUpstream: artifact '${name}' lacks AOS fixed-output instrumentation");
              in
                if actual.schema != "aos.fixed-output/v1"
                then throw "mkUpstream: artifact '${name}' has an incompatible fixed-output contract"
                else if actual.kind != value.materializer.kind
                then throw "mkUpstream: artifact '${name}' materializer kind disagrees with its derivation"
                else
                  value
                  // {
                    derivation = actual.outputDerivation;
                  }
            )
            normalizedArtifacts;
      in
        normalized
        // {
          inherit artifacts;
          members = [member];
          platforms = [platform];
        };
    }
