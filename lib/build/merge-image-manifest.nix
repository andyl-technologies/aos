##! lib/build/merge-image-manifest.nix — merge runtime config with image state
##!
##! Runtime evaluation compares the host/package candidate with an evaluation
##! of the same image modules without those inputs. Unchanged values retain the
##! exact image artifact, while explicit changes select the candidate. Generated
##! job-script changes also select their otherwise text-identical unit body.
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
  presetKey = preset: "${preset.unit}:${preset.source}";
  candidatePresets = listBy presetKey candidate.presets;
  baselinePresets = listBy presetKey baseline.presets;
  imagePresets = listBy presetKey imageManifest.presets;
  candidateStorePaths = listBy (path: path) candidate.storePaths;
  imageStorePaths = listBy (path: path) imageManifest.storePaths;

  changedFromBaseline = name: baselineValues: candidateValues: let
    baselineHas = builtins.hasAttr name baselineValues;
    candidateHas = builtins.hasAttr name candidateValues;
  in
    baselineHas != candidateHas
    || (candidateHas && candidateValues.${name} != baselineValues.${name});

  jobScriptChangedForUnit = unit: let
    prefix = "${unit}:";
    keys = builtins.attrNames (baseline.jobScripts // candidate.jobScripts);
  in
    builtins.any
    (key:
      lib.hasPrefix prefix key
      && changedFromBaseline key baseline.jobScripts candidate.jobScripts)
    keys;
  unitChangedFromBaseline = name:
    changedFromBaseline name baseline.units candidate.units
    || jobScriptChangedForUnit name;
  etcChangedFromBaseline = path:
    changedFromBaseline path baseline.etc candidate.etc
    || builtins.any
    (unit: path == "systemd/system/${unit}" && jobScriptChangedForUnit unit)
    (builtins.attrNames (baseline.units // candidate.units));

  mergeImageDefaultsBy = changed: imageValues: baselineValues: candidateValues:
    builtins.listToAttrs (builtins.concatMap
      (name:
        if changed name
        then
          if builtins.hasAttr name candidateValues
          then [{inherit name; value = candidateValues.${name};}]
          else []
        else if builtins.hasAttr name imageValues
        then [{inherit name; value = imageValues.${name};}]
        else if builtins.hasAttr name candidateValues
        then [{inherit name; value = candidateValues.${name};}]
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
      owner =
        if fromImage
        then imageOwners.${name} or "@base"
        else candidateOwners.${name} or "@base";
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
  mergedUnits = mergeImageDefaultsBy unitChangedFromBaseline imageManifest.units baseline.units candidate.units;
  mergedJobScripts = mergeImageDefaults imageManifest.jobScripts baseline.jobScripts candidate.jobScripts;
  mergedUsers = mergeImageDefaults imageUsers baselineUsers candidateUsers;
  mergedPresets = mergeImageDefaults imagePresets baselinePresets candidatePresets;
  mergedStorePaths = imageStorePaths // candidateStorePaths;
  removedEtc = builtins.filter
    (name: !(builtins.hasAttr name mergedEtc))
    (builtins.attrNames imageManifest.etc);
in
  candidate
  // {
    etc = mergedEtc;
    inherit removedEtc;
    units = mergedUnits;
    jobScripts = mergedJobScripts;
    users = builtins.attrValues mergedUsers;
    presets = builtins.attrValues mergedPresets;
    storePaths = builtins.attrNames mergedStorePaths;
    ownership = candidate.ownership // {
      etc = mergeOwnersBy
        etcChangedFromBaseline
        mergedEtc
        imageManifest.etc
        imageManifest.ownership.etc
        candidate.ownership.etc;
      units = mergeOwnersBy
        unitChangedFromBaseline
        mergedUnits
        imageManifest.units
        imageManifest.ownership.units
        candidate.ownership.units;
      jobScripts = mergeOwners
        imageManifest.jobScripts
        baseline.jobScripts
        candidate.jobScripts
        imageManifest.ownership.jobScripts
        candidate.ownership.jobScripts;
      users = mergeOwners
        imageUsers
        baselineUsers
        candidateUsers
        imageManifest.ownership.users
        candidate.ownership.users;
      presets = mergeOwners
        imagePresets
        baselinePresets
        candidatePresets
        imageManifest.ownership.presets
        candidate.ownership.presets;
      # An immutable image path remains image-owned when host configuration
      # also references it.
      storePaths = candidate.ownership.storePaths // imageManifest.ownership.storePaths;
    };
  }
