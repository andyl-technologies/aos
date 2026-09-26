##! Maps canonical package identities into one checked immutable read view.
{lib}: let
  pathComponents = path: lib.splitString "/" path;

  isAbsoluteNormalPath = path:
    builtins.isString path
    && path != "/"
    && lib.hasPrefix "/" path
    && !lib.hasSuffix "/" path
    && builtins.all (component: component != "" && component != "." && component != "..") (
      builtins.tail (pathComponents path)
    );

  validate = storeView: let
    exactShape =
      builtins.isAttrs storeView
      && builtins.attrNames storeView
      == [
        "identity_root"
        "read_root"
        "schema"
        "static_contract"
      ];
    identityRoot = storeView.identity_root or null;
    readRoot = storeView.read_root or null;
    staticContract = storeView.static_contract or null;
    staticPrefix =
      if builtins.isString identityRoot
      then "${identityRoot}/"
      else "";
    staticRelative =
      if builtins.isString staticContract && lib.hasPrefix staticPrefix staticContract
      then lib.removePrefix staticPrefix staticContract
      else "";
  in
    if
      !exactShape
      || storeView.schema != "aos.package-store.read-view-locator/v1"
      || !isAbsoluteNormalPath identityRoot
      || !isAbsoluteNormalPath readRoot
      || !isAbsoluteNormalPath staticContract
      || builtins.match "[^/]+/contract\\.json" staticRelative == null
    then throw "base-lib: invalid checked package-store read-view locator"
    else storeView;

  readPathFor = storeView: identity: let
    checked = validate storeView;
    identityPath = builtins.toString identity;
    prefix = "${checked.identity_root}/";
  in
    if !isAbsoluteNormalPath identityPath || !lib.hasPrefix prefix identityPath
    then throw "base-lib: canonical identity path '${identityPath}' is outside the checked package-store view"
    else "${checked.read_root}/${lib.removePrefix prefix identityPath}";

  mapOutputs = storeView: outputs: {
    self = readPathFor storeView outputs.self;
    dependencies = builtins.mapAttrs (_: readPathFor storeView) outputs.dependencies;
  };

  mapAuthenticatedModule = storeView: record:
    record
    // {
      configRoot = readPathFor storeView record.configRoot;
      module = readPathFor storeView record.module;
      outputs = mapOutputs storeView record.outputs;
    };
  contextualizeModule = roots: record: let
    root = builtins.unsafeDiscardStringContext (builtins.toString record.configRoot);
    module = builtins.toString record.module;
    fetched = roots.${root} or null;
  in
    if fetched == null
    then record
    else if !lib.hasPrefix "${root}/" module
    then throw "base-lib: authenticated module is outside its fetched config root"
    else record // {module = fetched + lib.removePrefix root module;};
  staticContractFor = storeView: identity: let
    checked = validate storeView;
  in
    if checked.static_contract != identity
    then throw "base-lib: store view does not authenticate the requested stage static contract"
    else {
      inherit identity;
      path = readPathFor checked identity;
    };
in {
  inherit validate readPathFor mapAuthenticatedModule contextualizeModule staticContractFor;
}
