# SPDX-License-Identifier: MIT
# Keeps native compilation independent of host/fixture source enrichment.
{
  mkDerivation,
  python3-3_12,
}: let
  makeNative = import ./native-compiler.nix {inherit mkDerivation;};
  nativeNames = ["unpack" "platform-source" "terminal-source" "build" "install"];
  hostNames = [
    "check"
    "platform-check"
    "platform-manifest"
    "terminal-check"
    "terminal-source-manifest"
    "terminal-inventory-check"
    "causal-device-check"
    "closed-block-check"
    "closed-network-check"
    "native-original-scope-source"
  ];
  makeFoundation = logical: let
    native = makeNative logical;
    hostPhases = builtins.filter (phase: !(builtins.elem phase.name nativeNames)) logical.phases;
    recipeRows =
      map (path: {
        inherit path;
        name = builtins.baseNameOf path;
        sha256 = builtins.hashFile "sha256" path;
      })
      logical.hostRecipes;
    publicRecipeRows = builtins.filter (row: row.name == "gem5.nix") recipeRows;
    recipeCopies = builtins.concatStringsSep "\n" (map (row: "cp ${row.path} \"$source/build/recipes/${row.name}\"") recipeRows);
    binding = builtins.toJSON {
      schema = "crucible.gem5.native-wrapper-inputs.v1";
      native_output = "${native}";
      native_source = "${native.source}";
      native_derivation = native.drvPath;
      host_recipes = recipeRows;
      public_recipe = builtins.head publicRecipeRows;
      host_controls = logical.hostControls;
      source_enrichment_recipe = ./foundation.nix;
      source_enrichment_writer = ./source-enrichment.py;
      source_enrichment_check = ./source-enrichment-check.py;
      node_authority_qualified = false;
    };
    privateFields = [
      "nativePatchFiles"
      "nativeRecipeSources"
      "nativeToolchain"
      "hostControls"
      "hostRecipes"
      "hostLicenseInventory"
      "phases"
      "passthru"
    ];
    package = assert builtins.length publicRecipeRows == 1;
    assert builtins.all (phase: builtins.elem phase.name (nativeNames ++ hostNames)) logical.phases;
      mkDerivation ((builtins.removeAttrs logical privateFields)
        // {
          outputs = ["out" "source"];
          passBuildScriptAsFile = true;
          runtimeDeps = logical.runtimeDeps ++ [native native.source];
          wrapperBinding = binding;
          passAsFile = ["wrapperBinding"];
          # The public output is an exact mirror, not another ELF transformation.
          dontStrip = true;
          dontPatchShebangs = true;
          dontPatchELF = true;
          dontMoveDocs = true;
          dontNukeRefs = true;
          phases =
            [
              {
                name = "source-enrichment";
                script = ''
                  mkdir -p native-work "$out" "$source"
                  cp -R ${native}/. "$out/"
                  cp -R ${native.source}/. "$source/"
                  chmod -R u+w "$out" "$source"
                  mkdir -p "$source/build/recipes" "$source/build/controls"
                  cp -R ${logical.hostControls}/. "$source/build/controls/"
                  ${recipeCopies}
                  cp ${logical.hostLicenseInventory} "$source/licenses/patch-inventory.md"
                  cp "$wrapperBindingPath" "$source/build/wrapper-inputs.json"
                  cp ${native}/share/gem5/source-manifest.json "$source/build/native-source-manifest.json"
                  cp "$0" "$source/build/invoked-enrichment-builder.sh"
                  cp ${./foundation.nix} "$source/build/source-enrichment.nix"
                  cp ${./source-enrichment.py} "$source/build/source-enrichment.py"
                  cp ${./source-enrichment-check.py} "$source/build/source-enrichment-check.py"
                  ln -s ${native.source} "$source/native-corresponding-source"
                  rm "$out/share/gem5/corresponding-source"
                  ln -s "$source" "$out/share/gem5/corresponding-source"
                  cd native-work
                  tar --no-same-owner -xf ${native.source}/gem5-patched-source.tar
                  tar --no-same-owner -xf ${native.source}/build/generated-headers.tar
                  cp ${native}/bin/gem5 build/ALL/gem5.opt
                '';
              }
            ]
            ++ hostPhases
            ++ [
              {
                name = "native-origin-binding";
                script = ''
                  ${python3-3_12}/bin/python3 ${logical.hostControls}/source-enrichment-check.py
                  ${python3-3_12}/bin/python3 ${./source-enrichment.py} \
                    "$wrapperBindingPath" "$out" "$source"
                '';
              }
              {
                name = "fixup";
                script = ''
                  # mkDerivation honors this explicit fixup and skips strip/RPATH.
                  # Its later scrub is explicitly disabled above. Recheck exact
                  # native ELF bytes after every package-specific phase.
                  ${python3-3_12}/bin/python3 ${./source-enrichment.py} \
                    "$wrapperBindingPath" "$out" "$source" verify
                '';
              }
            ];
          passthru = (logical.passthru or {}) // {nativeCompiler = native;};
        });
  in
    # Preserve AOS mkDerivation's existing one-argument overrideAttrs API while
    # recomputing both layers from the original logical package definition.
    package
    // {
      overrideAttrs = override:
        makeFoundation (logical
          // (
            if builtins.isFunction override
            then override logical
            else override
          ));
      override = override:
        makeFoundation (
          if builtins.isFunction override
          then override logical
          else logical // override
        );
    };
in
  makeFoundation
