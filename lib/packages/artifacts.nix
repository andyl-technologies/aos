##! Explicit realized artifacts shared by package builds and deployment evaluation.
{}: let
  nameFor = package: package.catalogName or package.pname or package.name;
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
  canonicalReference = package:
    canonical (sourceContexts
      (package.deployment.package or (reference package)) (reference package));
  canonicalDependencies = package: let
    source = keyed (package.runtimeDeps or []);
    declared = package.deployment.runtimeDependencies or source;
  in
    builtins.mapAttrs (name: dependency:
      sourceContexts dependency (source.${name} or dependency))
    declared;
  keyed = packages:
    builtins.foldl' (result: package: let
      name = nameFor package;
      value = reference package;
    in
      if result ? ${name} && result.${name} != value
      then throw "Package dependency '${name}' resolves to conflicting artifacts."
      else result // {${name} = value;}) {}
    packages;
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
  envelope = package: {
    schema = "aos.package.deployment";
    system = package.targetSystem or package.system;
    package = metadata (reference package);
    module =
      if package ? module
      then moduleReference package
      else null;
    runtimeDependencies = builtins.mapAttrs (_: metadata) (keyed (package.runtimeDeps or []));
    moduleDependencies = builtins.map moduleReference (package.moduleDeps or []);
  };
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
    graphContexts = builtins.getContext (builtins.toJSON graph);
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
in {inherit nameFor reference metadata canonical canonicalReference canonicalDependencies keyed unique moduleReference envelope value valid graphInputs;}
