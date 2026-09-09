##! Validates package-authored ability declarations and prepares their closed
##! JSON projection. Realized artifact identities are filled by the fixed
##! companion builder from Nix's exported reference graph.
{
  lib,
  abilities,
}: let
  placeholderDigest = "sha256:${lib.concatStrings (builtins.genList (_: "0") 64)}";

  fail = packageName: message:
    throw "mkDerivation abilityPackage for package '${packageName}' ${message}";

  requireAttrs = packageName: context: allowed: value: let
    unknown =
      if builtins.isAttrs value
      then builtins.filter (name: !(builtins.elem name allowed)) (builtins.attrNames value)
      else [];
  in
    if !builtins.isAttrs value
    then fail packageName "field '${context}' must be an attrset"
    else if unknown != []
    then fail packageName "field '${context}' contains unknown keys: ${builtins.concatStringsSep ", " unknown}"
    else value;

  placeholderArtifact = path:
    abilities.artifactReference {
      content = placeholderDigest;
      storePath = "${path}";
      narHash = placeholderDigest;
      closure = placeholderDigest;
    };

  validLocalKey = value:
    builtins.isString value
    && builtins.stringLength value > 0
    && builtins.stringLength value <= 128
    && builtins.match "[A-Za-z0-9._-]+" value != null;

  validateScope = packageName: scope:
    if !builtins.isList scope || !(lib.all validLocalKey scope)
    then fail packageName "contains an invalid ownership scope"
    else scope;
in {
  prepare = {
    packageName,
    version,
    payload,
    source,
    abilityPackage,
  }: let
    checked =
      requireAttrs packageName "abilityPackage" [
        "activationMode"
        "artifacts"
        "exports"
        "handlers"
        "ownership"
        "requiredFeatures"
        "requirements"
      ]
      abilityPackage;
    activationMode = checked.activationMode or "contracts-only";
    requiredFeatures = lib.sort builtins.lessThan (lib.unique (checked.requiredFeatures or ["abilities-v1"]));
    authoredExports = checked.exports or {};
    authoredHandlers = checked.handlers or {};

    preparedExports =
      builtins.mapAttrs (name: value: let
        entry = requireAttrs packageName "abilityPackage.exports.${name}" ["artifact" "export" "requiredFeatures"] value;
        artifact = entry.artifact or (fail packageName "export '${name}' must set artifact");
        authored = entry.export or (fail packageName "export '${name}' must set export");
        interfaceDocument = abilities.interfaceDocument (entry.requiredFeatures or []) authored;
        pinned = abilities.pinInterface {
          export = authored;
          descriptor = placeholderDigest;
        };
      in {
        inherit artifact interfaceDocument;
        declaration = abilities.normalizeExportDeclaration name placeholderDigest pinned;
        implementation = abilities.normalizeImplementation (placeholderArtifact artifact) pinned;
        composeEntry = pinned.compose_entry;
        transitionEntry = pinned.transition_entry;
        handler = pinned.handler;
      })
      authoredExports;

    preparedHandlers =
      builtins.mapAttrs (name: value: let
        entry = requireAttrs packageName "abilityPackage.handlers.${name}" ["arguments" "artifact" "entryPoint" "result"] value;
      in {
        artifact = entry.artifact or (fail packageName "handler '${name}' must set artifact");
        entry_point = entry.entryPoint or (fail packageName "handler '${name}' must set entryPoint");
        arguments = abilities.schemas.validateSchema "ability handler '${name}' arguments" entry.arguments;
        result = abilities.schemas.validateSchema "ability handler '${name}' result" entry.result;
      })
      authoredHandlers;

    exportNames = builtins.attrNames preparedExports;
    handlerNames = builtins.attrNames preparedHandlers;
    featureCheck =
      if !(builtins.elem activationMode ["contracts-only" "structured-effects"])
      then fail packageName "has unsupported activationMode '${toString activationMode}'"
      else if !(builtins.isList requiredFeatures) || !(lib.all (feature: feature == "abilities-v1") requiredFeatures)
      then fail packageName "requires an unsupported package feature"
      else true;
    handlerLinkCheck = lib.all (name: let
      export = preparedExports.${name};
    in
      export.handler
      == null
      || (
        builtins.hasAttr export.handler preparedHandlers
        && "${preparedHandlers.${export.handler}.artifact}"
        == "${export.artifact}"
      ))
    exportNames;
    explicitArtifacts = checked.artifacts or [];
    implementationPaths = builtins.map (name: preparedExports.${name}.artifact) exportNames;
    handlerPaths = builtins.map (name: preparedHandlers.${name}.artifact) handlerNames;
    artifactPaths = lib.unique (implementationPaths ++ handlerPaths ++ explicitArtifacts);
    allPaths = lib.unique ([payload source] ++ artifactPaths);
    graphNames = builtins.genList (index: "abilityArtifact${toString index}") (builtins.length allPaths);
    referenceGraph = builtins.listToAttrs (builtins.genList (index: {
        name = builtins.elemAt graphNames index;
        value = [(builtins.elemAt allPaths index)];
      })
      (builtins.length allPaths));
    graphSpecs = builtins.genList (index: {
      name = builtins.elemAt graphNames index;
      path = "${builtins.elemAt allPaths index}";
    }) (builtins.length allPaths);

    entryPointPairs = lib.concatMap (name: let
      entry = preparedExports.${name};
    in
      lib.optional (entry.composeEntry != null) {
        name = entry.composeEntry;
        value = placeholderArtifact entry.artifact;
      }
      ++ lib.optional (entry.transitionEntry != null) {
        name = entry.transitionEntry;
        value = placeholderArtifact entry.artifact;
      })
    exportNames;
    entryPointNames = builtins.map (entry: entry.name) entryPointPairs;
    entryPoints =
      if builtins.length entryPointNames != builtins.length (lib.unique entryPointNames)
      then fail packageName "reuses a module entry-point name"
      else builtins.listToAttrs entryPointPairs;

    template = {
      schema = "aos.ability.package/v1";
      required_features = requiredFeatures;
      activation_mode = activationMode;
      package = {
        name = packageName;
        inherit version;
        payload = placeholderArtifact payload;
        source = placeholderArtifact source;
      };
      artifacts = builtins.map placeholderArtifact artifactPaths;
      exports = builtins.map (name: preparedExports.${name}.declaration) exportNames;
      requirements = abilities.normalizeRequirements (checked.requirements or {});
      module_entry_points = entryPoints;
      implementation = {
        providers = builtins.map (name: preparedExports.${name}.implementation) exportNames;
        handlers =
          builtins.mapAttrs (_: handler: {
            artifact = placeholderArtifact handler.artifact;
            inherit (handler) entry_point arguments result;
          })
          preparedHandlers;
      };
      ownership = builtins.map (validateScope packageName) (checked.ownership or []);
    };

    interfaces =
      builtins.map (name: {
        inherit name;
        document = preparedExports.${name}.interfaceDocument;
      })
      exportNames;
  in
    assert featureCheck;
    assert handlerLinkCheck || fail packageName "contains a terminal export without an exact same-artifact handler"; {
      inherit allPaths graphSpecs interfaces referenceGraph template;
      templateJson = builtins.toJSON template;
      graphSpecsJson = builtins.toJSON graphSpecs;
      interfacesJson = builtins.toJSON interfaces;
    };
}
