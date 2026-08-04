##! pkgs/build-support/_config-module-renderer.nix - configuration-module
##! output preparation.
##!
##! Validates a package-authored `configModule` attrset and returns the build
##! inputs used to populate the package's trusted `config` artifact.
##! The output contains `module.nix`, private relative-imported `.nix` helpers,
##! and a generated `config-meta.json` interface manifest.
##!
##! The package's authored builder cannot write the `config` artifact. A fixed
##! companion derivation copies only the local source and generated metadata,
##! rejects symlinks, non-Nix helpers, and literal store-path constructions,
##! and has an empty Nix reference set.
##!
##! ## `configModule` schema
##!
##! ```nix
##! configModule = {
##!   src = ./config-module;
##!   moduleAbiCompat = { min = 1; max = 1; };
##!   declares = [ "firewall.allowedTCPPorts" ];
##!   ownsRoots = [
##!     {
##!       root = "firewall";
##!       interfaceAbi = 1;
##!       contributable = [ "allowedTCPPorts" ];
##!     }
##!   ];
##!   contributes = [
##!     {
##!       root = "nginx";
##!       interfaceAbi = 1;
##!       paths = [ "virtualHosts.example" ];
##!     }
##!   ];
##!   providesCapabilities = [];
##! };
##! ```
{lib}: let
  throwIfNot = lib.throwIfNot;

  knownKeys = [
    "src"
    "moduleAbiCompat"
    "declares"
    "ownsRoots"
    "contributes"
    "providesCapabilities"
  ];

  validateList = packageName: field: value:
    throwIfNot
    (builtins.isList value)
    "configModule for package '${packageName}' field '${field}' must be a list"
    value;

  validateOptionPath = packageName: field: value:
    throwIfNot
    (builtins.isString value
      && builtins.match "[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*" value != null)
    "configModule for package '${packageName}' field '${field}' contains invalid option path '${toString value}'"
    value;

  validateSurfacePath = packageName: field: value:
    throwIfNot
    (builtins.isString value
      && builtins.match "(\\*|[A-Za-z0-9_-]+)(\\.(\\*|[A-Za-z0-9_-]+))*" value != null)
    "configModule for package '${packageName}' field '${field}' contains invalid contribution surface '${toString value}'; '*' must occupy a complete dotted path segment"
    value;

  validateRoot = packageName: field: value:
    throwIfNot
    (builtins.isString value && builtins.match "[A-Za-z0-9_-]+" value != null)
    "configModule for package '${packageName}' field '${field}' contains invalid root '${toString value}'"
    value;

  validateUnique = packageName: field: values:
    throwIfNot
    (builtins.length values == builtins.length (lib.unique values))
    "configModule for package '${packageName}' field '${field}' contains duplicate entries"
    values;

  validatePathList = packageName: field: value:
    validateUnique packageName field (
      builtins.map (validateOptionPath packageName field) (validateList packageName field value)
    );

  validateSurfaceList = packageName: field: value:
    validateUnique packageName field (
      builtins.map (validateSurfacePath packageName field) (validateList packageName field value)
    );

  surfaceMatches = surface: concrete: let
    go = expected: actual:
      if expected == []
      then true
      else if actual == []
      then false
      else
        let
          expectedSegment = builtins.head expected;
          actualSegment = builtins.head actual;
        in
          (expectedSegment == "*" || expectedSegment == actualSegment)
          && go (builtins.tail expected) (builtins.tail actual);
  in
    go (lib.splitString "." surface) (lib.splitString "." concrete);

  validateRecordKeys = packageName: field: known: value: let
    checked =
      throwIfNot
      (builtins.isAttrs value)
      "configModule for package '${packageName}' field '${field}' entries must be attrsets"
      value;
    unknown = builtins.filter (key: !(builtins.elem key known)) (builtins.attrNames checked);
  in
    throwIfNot
    (unknown == [])
    "configModule for package '${packageName}' field '${field}' contains unknown keys: ${builtins.concatStringsSep ", " unknown}"
    checked;

  prepare = {
    packageName,
    configModule,
  }: let
    checkedModule =
      throwIfNot
      (builtins.isAttrs configModule)
      "mkDerivation configModule for package '${packageName}' must be an attrset"
      configModule;
    extraKeys = builtins.filter (key: !(builtins.elem key knownKeys)) (builtins.attrNames checkedModule);
    source =
      checkedModule.src
      or (throw "configModule for package '${packageName}' must set 'src' (the directory containing module.nix)");
    checkedSource =
      throwIfNot
      (builtins.isPath source)
      "configModule for package '${packageName}' field 'src' must be a local path"
      source;
    modulePath = checkedSource + "/module.nix";
    abiCompat =
      checkedModule.moduleAbiCompat or {
        min = 1;
        max = 1;
      };
    abiMin = abiCompat.min or 1;
    abiMax = abiCompat.max or 1;
    declares = validatePathList packageName "declares" (checkedModule.declares or []);
    ownsRoots =
      builtins.map (
        value: let
          root = validateRecordKeys packageName "ownsRoots" ["root" "interfaceAbi" "contributable"] value;
          rootName = validateRoot packageName "ownsRoots.root" (root.root or "");
          interfaceAbi = root.interfaceAbi or abiMin;
          contributable = validateSurfaceList packageName "ownsRoots.contributable" (root.contributable or []);
        in
          throwIfNot
          (builtins.isInt interfaceAbi && interfaceAbi >= 0 && interfaceAbi <= 4294967295)
          "configModule for package '${packageName}' field 'ownsRoots.interfaceAbi' must fit an unsigned 32-bit integer"
          {
            root = rootName;
            inherit interfaceAbi contributable;
          }
      )
      (validateList packageName "ownsRoots" (checkedModule.ownsRoots or []));
    contributes =
      builtins.map (
        value: let
          contribution = validateRecordKeys packageName "contributes" ["root" "interfaceAbi" "paths"] value;
          root = validateRoot packageName "contributes.root" (contribution.root or "");
          interfaceAbi =
            contribution.interfaceAbi
            or (throw "legacy configModule contribution to '${root}' in package '${packageName}' has no interfaceAbi; republish it against the owner's current interface ABI");
          paths = validatePathList packageName "contributes.paths" (contribution.paths or []);
        in
          throwIfNot
          (builtins.isInt interfaceAbi && interfaceAbi >= 0 && interfaceAbi <= 4294967295)
          "configModule for package '${packageName}' contribution to '${root}' field 'interfaceAbi' must fit an unsigned 32-bit integer"
          (throwIfNot
            (paths != [])
            "configModule for package '${packageName}' contribution to '${root}' must list at least one path"
            {inherit root interfaceAbi paths;})
      )
      (validateList packageName "contributes" (checkedModule.contributes or []));
    providesCapabilities =
      validatePathList packageName "providesCapabilities" (checkedModule.providesCapabilities or []);
    ownedRootNames = builtins.map (root: root.root) ownsRoots;
    contributedRootNames = builtins.map (contribution: contribution.root) contributes;
    contributionAuthorizes = declaredPath: contribution: let
      rootPrefix = "${contribution.root}.";
      relativePath = lib.removePrefix rootPrefix declaredPath;
    in
      lib.hasPrefix rootPrefix declaredPath
      && builtins.any (contributedPath: surfaceMatches contributedPath relativePath)
      contribution.paths;
    foreignDeclares =
      builtins.filter (
        path: let
          root = builtins.head (lib.splitString "." path);
        in
          root != packageName
          && !(builtins.elem root ownedRootNames)
          && !(builtins.any (contributionAuthorizes path) contributes)
      )
      declares;
    metaJson = builtins.toJSON {
      schema = "aos.config-module-meta/v1";
      module_abi_compat = {
        min = abiMin;
        max = abiMax;
      };
      inherit declares;
      owns_roots =
        builtins.map (root: {
          inherit (root) root contributable;
          interface_abi = root.interfaceAbi;
        })
        ownsRoots;
      contributes =
        builtins.map (contribution: {
          inherit (contribution) root paths;
          interface_abi = contribution.interfaceAbi;
        })
        contributes;
      provides_capabilities = providesCapabilities;
    };
  in
    throwIfNot
    (extraKeys == [])
    "mkDerivation configModule for package '${packageName}' contains unknown keys: ${builtins.concatStringsSep ", " extraKeys}"
      (throwIfNot
        (builtins.isAttrs abiCompat
        && builtins.attrNames abiCompat == ["max" "min"]
        && builtins.isInt abiMin
        && builtins.isInt abiMax)
      "configModule for package '${packageName}' must set an integer moduleAbiCompat min/max band"
      (throwIfNot
        (abiMin >= 0 && abiMin <= abiMax && abiMax <= 4294967295)
        "configModule for package '${packageName}' has an invalid unsigned 32-bit moduleAbiCompat band: min ${toString abiMin}, max ${toString abiMax}"
        (throwIfNot
          (builtins.length ownedRootNames == builtins.length (lib.unique ownedRootNames))
          "configModule for package '${packageName}' owns a root more than once"
          (throwIfNot
            (builtins.length contributedRootNames == builtins.length (lib.unique contributedRootNames))
            "configModule for package '${packageName}' contributes to a root more than once"
            (throwIfNot
              (builtins.all (root: !(builtins.elem root ownedRootNames)) contributedRootNames)
              "configModule for package '${packageName}' cannot both own and contribute to the same root"
              (throwIfNot
                (foreignDeclares == [])
                "configModule for package '${packageName}' declares paths outside its ownsRoots/contributes.paths authorization: ${builtins.concatStringsSep ", " foreignDeclares}"
                (throwIfNot
                  (builtins.pathExists modulePath)
                  "configModule for package '${packageName}' has no module.nix at ${toString checkedSource}"
                  {
                    src = builtins.path {
                      path = checkedSource;
                      name = "config-module-source-${packageName}";
                    };
                    inherit metaJson;
                  })))))));
in {
  inherit prepare;
}
