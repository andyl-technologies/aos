##! Explicit realized artifacts shared by package builds and deployment evaluation.
{}: let
  moduleDependencies = import ./module-dependencies.nix;
  versions = import ./version.nix;
  nameFor = package: package.catalogName or package.pname or package.name;
  releaseIdentity = package: let
    versionRequirement = versions.requirementFor package;
  in
    {
      name = nameFor package;
      version = package.version or "0";
    }
    // (
      if versionRequirement == null
      then {}
      else {inherit versionRequirement;}
    );
  reference = package: {
    name = nameFor package;
    version = package.version or "0";
    path = builtins.toString package;
    outputs = builtins.listToAttrs (builtins.map (output: {
      name = output;
      value = builtins.toString (package.${output} or package);
    }) (package.outputs or ["out"]));
    mainProgram = package.meta.mainProgram or package.pname or null;
  };
  # Catalog locators authenticate availability without retaining every payload.
  metadata = artifact:
    artifact
    // {
      path = builtins.unsafeDiscardStringContext artifact.path;
      outputs = builtins.mapAttrs (_: builtins.unsafeDiscardStringContext) artifact.outputs;
    };
  canonical = artifact: let
    catalog = artifact;
    output =
      if catalog.outputs ? out
      then "out"
      else builtins.head (builtins.attrNames catalog.outputs);
  in
    catalog // {path = catalog.outputs.${output};};
  sourceContexts = declared: source: let
    restore = path: let
      matching = builtins.filter (candidate: candidate == path) (builtins.attrValues source.outputs);
    in
      if matching == []
      then path
      else builtins.head matching;
  in
    declared
    // {
      path = restore declared.path;
      outputs = builtins.mapAttrs (_: restore) declared.outputs;
    };
  canonicalReference = package: let
    source = reference package;
    declared = package.deployment.package or source;
  in
    if metadata (canonical declared) != metadata (canonical source)
    then throw "Package '${nameFor package}' deployment catalog differs from its actual artifact outputs. Regenerate native companions when changing outputs."
    else canonical (sourceContexts declared source);
  # Runtime bindings may name roles independently of the artifact's identity.
  # Builders consume the values; retained modules consume the same named map.
  dependencyValues = packages:
    if builtins.isList packages
    then packages
    else if builtins.isAttrs packages && !(packages ? type && packages.type == "derivation")
    then builtins.attrValues packages
    else throw "Runtime dependencies must be a list or a named attribute set.";
  keyed = packages:
    if builtins.isAttrs packages
    then
      builtins.mapAttrs (name: package:
        if name == ""
        then throw "Runtime dependency binding names must not be empty."
        else reference package)
      packages
    else
      builtins.foldl' (result: package: let
        name = nameFor package;
        value = reference package;
      in
        if result ? ${name} && result.${name} != value
        then throw "Package dependency '${name}' resolves to conflicting artifacts; use explicit runtime dependency binding names."
        else result // {${name} = value;}) {}
      (dependencyValues packages);
  canonicalDependencies = package: let
    dependencies = package.runtimeDeps or [];
    source = builtins.map reference (dependencyValues dependencies);
    declared = package.deployment.runtimeDependencies or (keyed dependencies);
  in
    builtins.mapAttrs (_: dependency: let
      matches = builtins.filter (candidate: metadata candidate == metadata dependency) source;
    in
      sourceContexts dependency (
        if matches == []
        then dependency
        else builtins.head matches
      ))
    declared;
  unique = references:
    builtins.attrValues (builtins.foldl' (result: artifact: let
      path = builtins.unsafeDiscardStringContext artifact.path;
    in
      if result ? ${path} && result.${path} != artifact
      then throw "Artifact '${path}' has conflicting package identities."
      else result // {${path} = artifact;}) {}
    references);
  moduleReference = package: {
    name = nameFor package;
    version = package.version or "0";
    source = "${package.module}";
    entrypoint = "module.nix";
  };
  envelope = package:
    {
      schema = "aos.package.deployment";
      system = package.targetSystem or package.system;
      package = metadata (reference package);
      module =
        if package ? module
        then moduleReference package
        else null;
      runtimeDependencies = builtins.mapAttrs (_: metadata) (keyed (package.runtimeDeps or []));
      moduleDependencies = moduleDependencies.references moduleReference (package.moduleDeps or []);
    }
    // builtins.removeAttrs (releaseIdentity package) ["name" "version"]
    // (
      if (package.osVersion or null) == null
      then {}
      else
        builtins.deepSeq ((import ./semver.nix).parseRequirement package.osVersion)
        {inherit (package) osVersion;}
    );
  valid = reference:
    builtins.isAttrs reference
    && builtins.attrNames reference == ["mainProgram" "name" "outputs" "path" "version"]
    && builtins.isString reference.name
    && builtins.isString reference.version
    && builtins.isString reference.path
    && builtins.match "/nix/store/[^/]+" reference.path != null
    && (reference.mainProgram == null || (builtins.isString reference.mainProgram && !builtins.elem reference.mainProgram ["." ".."] && builtins.match "[A-Za-z0-9+._-]+" reference.mainProgram != null))
    && builtins.isAttrs reference.outputs
    && builtins.elem reference.path (builtins.attrValues reference.outputs)
    && builtins.all (path: builtins.isString path && builtins.match "/nix/store/[^/]+" path != null) (builtins.attrValues reference.outputs);
  # These are artifact values, deliberately not pretend derivations. Their
  # string coercion permits ordinary interpolation in module configuration.
  value = reference: let
    attach = path: let
      root = builtins.unsafeDiscardStringContext path;
    in
      if builtins.getContext path != {}
      then path
      else builtins.appendContext root {${root} = {path = true;};};
    base = path: let
      selected = attach path;
    in
      reference
      // {
        _type = "aos-package-artifact";
        path = selected;
        outPath = selected;
        outputs = builtins.mapAttrs (_: attach) reference.outputs;
        __toString = _: selected;
        meta =
          if reference.mainProgram == null
          then {}
          else {inherit (reference) mainProgram;};
      };
    outputs = builtins.mapAttrs (_: path: base path // outputs) reference.outputs;
  in
    base reference.path // outputs;

  # Only coercions of authenticated artifact values contribute payload roots.
  graphInputs = {
    graph,
    packageArtifacts ? [],
    packageModules ? [],
    evaluationInputs ? [],
  }: let
    operationalNodes = builtins.map (node: {
      inherit (node) input handler;
      after = node.after or [];
    }) (builtins.attrValues graph.nodes);
    graphContexts = builtins.getContext (builtins.toJSON operationalNodes);
    availableRoots =
      builtins.concatLists (builtins.map (record:
        builtins.concatLists (builtins.map (artifact: builtins.attrValues artifact.outputs)
          ([record.artifacts.package] ++ builtins.attrValues record.artifacts.dependencies)))
      packageModules)
      ++ builtins.concatLists (builtins.map (artifact: builtins.attrValues artifact.outputs) packageArtifacts);
    sourceRoots = builtins.map (input: "${input}") evaluationInputs ++ builtins.map (record: "${record.configRoot}") packageModules;
    graphRoots = builtins.concatLists (builtins.map (root: let
      context = graphContexts.${root};
      matches = builtins.filter (path: let
        candidate = (builtins.getContext path).${root} or {};
      in
        builtins.any (output: builtins.elem output (candidate.outputs or [])) (context.outputs or []))
      (availableRoots ++ sourceRoots);
    in
      if context ? outputs
      then
        if matches == []
        then [root]
        else matches
      else [root]) (builtins.attrNames graphContexts));
    invalidRoots = builtins.filter (root: !(builtins.elem root (availableRoots ++ sourceRoots))) graphRoots;
    retainedRoots = builtins.attrNames (builtins.listToAttrs (builtins.map (root: {
      name = builtins.unsafeDiscardStringContext root;
      value = true;
    }) (sourceRoots ++ graphRoots)));
    inputs = builtins.map (root: let
      originals = builtins.filter (path: path == root) (availableRoots ++ sourceRoots);
      original =
        if originals == []
        then root
        else builtins.head originals;
    in
      if builtins.getContext original != {}
      then original
      else
        builtins.appendContext (builtins.unsafeDiscardStringContext root) {
          ${builtins.unsafeDiscardStringContext root} = {path = true;};
        }) (builtins.sort builtins.lessThan retainedRoots);
  in
    if invalidRoots != []
    then throw "Effect graph references artifacts outside its authenticated package catalogs: ${builtins.concatStringsSep ", " invalidRoots}"
    else inputs;
in {inherit nameFor releaseIdentity reference metadata canonical canonicalReference canonicalDependencies dependencyValues keyed unique moduleReference envelope value valid graphInputs;}
