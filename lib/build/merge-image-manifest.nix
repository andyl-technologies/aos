##! lib/build/merge-image-manifest.nix — merge runtime config with image state
##!
##! Runtime evaluation compares the host/package candidate with an evaluation
##! of the same image modules without those inputs. Unchanged values retain the
##! exact image artifact, while explicit changes select the candidate. Generated
##! job-script changes also select an otherwise text-identical referring file.
{lib}: {
  imageManifest,
  baseline,
  candidate,
}: let
  listBy = keyOf: values:
    builtins.listToAttrs (builtins.map
      (value: {
        name = keyOf value;
        inherit value;
      })
      values);

  candidateUsers = listBy (user: user.name) candidate.users;
  baselineUsers = listBy (user: user.name) baseline.users;
  imageUsers = listBy (user: user.name) imageManifest.users;
  candidateStorePaths = listBy (path: path) candidate.storePaths;
  imageStorePaths = listBy (path: path) imageManifest.storePaths;
  imageStaticOwners = lib.unique (builtins.concatMap builtins.attrValues [
    imageManifest.ownership.etc
    imageManifest.ownership.jobScripts
    imageManifest.ownership.users
    imageManifest.ownership.storePaths
  ]);

  # Image modules may carry package provenance, but their shipped artifacts
  # belong to the immutable base. Only runtime-selected packages participate
  # in degraded package projection after activation.
  runtimeOwner = owner:
    if owner == "@base" || owner == "@host" || builtins.elem owner (candidate.packages or [])
    then owner
    else if builtins.elem owner imageStaticOwners
    then "@base"
    else owner;

  changedFromBaseline = name: baselineValues: candidateValues: let
    baselineHas = builtins.hasAttr name baselineValues;
    candidateHas = builtins.hasAttr name candidateValues;
  in
    baselineHas
    != candidateHas
    || (candidateHas && candidateValues.${name} != baselineValues.${name});

  changedJobScriptReferencedBy = path: let
    entryText = manifest:
      if builtins.hasAttr path manifest.etc
      then manifest.etc.${path}.text or ""
      else "";
    baselineText = entryText baseline;
    candidateText = entryText candidate;
  in
    builtins.any
    (key:
      changedFromBaseline key baseline.jobScripts candidate.jobScripts
      && (
        lib.hasInfix "#aos-jobscript:${key}#" baselineText
        || lib.hasInfix "#aos-jobscript:${key}#" candidateText
      ))
    (builtins.attrNames (baseline.jobScripts // candidate.jobScripts));
  etcChangedFromBaseline = path:
    changedFromBaseline path baseline.etc candidate.etc
    || changedJobScriptReferencedBy path;

  mergeImageDefaultsBy = changed: imageValues: baselineValues: candidateValues:
    builtins.listToAttrs (builtins.concatMap
      (name:
        if changed name
        then
          if builtins.hasAttr name candidateValues
          then [
            {
              inherit name;
              value = candidateValues.${name};
            }
          ]
          else []
        else if builtins.hasAttr name imageValues
        then [
          {
            inherit name;
            value = imageValues.${name};
          }
        ]
        else if builtins.hasAttr name candidateValues
        then [
          {
            inherit name;
            value = candidateValues.${name};
          }
        ]
        else [])
      (builtins.attrNames (imageValues // baselineValues // candidateValues)));
  mergeImageDefaults = imageValues: baselineValues: candidateValues:
    mergeImageDefaultsBy
    (name: changedFromBaseline name baselineValues candidateValues)
    imageValues
    baselineValues
    candidateValues;
  mergeOwnersBy = changed: mergedValues: imageValues: imageOwners: candidateOwners:
    builtins.mapAttrs
    (name: _: let
      valueChanged = changed name;
      fromImage = !valueChanged && builtins.hasAttr name imageValues;
      owner = runtimeOwner (
        if fromImage
        then imageOwners.${name} or "@base"
        else candidateOwners.${name} or "@base"
      );
    in
      if !fromImage && valueChanged && owner == "@base"
      then "@host"
      else owner)
    mergedValues;
  mergeOwners = imageValues: baselineValues: candidateValues:
    mergeOwnersBy
    (name: changedFromBaseline name baselineValues candidateValues)
    (mergeImageDefaults imageValues baselineValues candidateValues)
    imageValues;

  mergedEtc = mergeImageDefaultsBy etcChangedFromBaseline imageManifest.etc baseline.etc candidate.etc;
  mergedJobScripts = mergeImageDefaults imageManifest.jobScripts baseline.jobScripts candidate.jobScripts;
  mergedUsers = mergeImageDefaults imageUsers baselineUsers candidateUsers;
  mergedStorePaths = imageStorePaths // candidateStorePaths;
  pathIsAncestor = ancestor: path: lib.hasPrefix "${ancestor}/" path;
  structurallyMasked = removedPath:
    builtins.any
    (mergedPath:
      pathIsAncestor removedPath mergedPath
      || pathIsAncestor mergedPath removedPath)
    (builtins.attrNames mergedEtc);
  removedEtc =
    builtins.filter
    (name:
      !(builtins.hasAttr name mergedEtc)
      && !structurallyMasked name)
    (builtins.attrNames imageManifest.etc);
in
  candidate
  // {
    etc = mergedEtc;
    inherit removedEtc;
    jobScripts = mergedJobScripts;
    users = builtins.attrValues mergedUsers;
    storePaths = builtins.attrNames mergedStorePaths;
    ownership =
      candidate.ownership
      // {
        etc =
          mergeOwnersBy
          etcChangedFromBaseline
          mergedEtc
          imageManifest.etc
          imageManifest.ownership.etc
          candidate.ownership.etc;
        jobScripts =
          mergeOwners
          imageManifest.jobScripts
          baseline.jobScripts
          candidate.jobScripts
          imageManifest.ownership.jobScripts
          candidate.ownership.jobScripts;
        users =
          mergeOwners
          imageUsers
          baselineUsers
          candidateUsers
          imageManifest.ownership.users
          candidate.ownership.users;
        # An immutable image path remains image-owned when host configuration
        # also references it.
        storePaths = builtins.mapAttrs (_: runtimeOwner) (candidate.ownership.storePaths // imageManifest.ownership.storePaths);
      };
  }
