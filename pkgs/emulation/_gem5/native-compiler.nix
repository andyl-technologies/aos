# SPDX-License-Identifier: MIT
# Builds only the native program and its exact native corresponding source.
{mkDerivation}: logical: let
  prefixNames = ["unpack" "platform-source" "terminal-source"];
  prefix = builtins.filter (phase: builtins.elem phase.name prefixNames) logical.phases;
  build = builtins.filter (phase: phase.name == "build") logical.phases;
  install = builtins.filter (phase: phase.name == "install") logical.phases;
  patchRows =
    map (path: {
      inherit path;
      name = builtins.baseNameOf path;
      sha256 = builtins.hashFile "sha256" path;
    })
    logical.nativePatchFiles;
  recipeRows =
    map (path: {
      inherit path;
      name = builtins.baseNameOf path;
      sha256 = builtins.hashFile "sha256" path;
    })
    logical.nativeRecipeSources;
  specification = builtins.toJSON {
    schema = "crucible.gem5.native-compiler-inputs.v1";
    patches = patchRows;
    recipes = recipeRows;
    toolchain = logical.nativeToolchain;
    commands = prefix ++ build ++ install;
    configuration = "ALL";
    source_snapshot = "after-variant-patches-before-generated-build-artifacts";
    node_authority_qualified = false;
  };
  patchCopies = builtins.concatStringsSep "\n" (map (row: "cp ${row.path} \"$source/patches/${row.name}\"") patchRows);
  recipeCopies = builtins.concatStringsSep "\n" (map (row: "cp ${row.path} \"$source/build/recipes/${row.name}\"") recipeRows);
  privateFields = [
    "nativePatchFiles"
    "nativeRecipeSources"
    "nativeToolchain"
    "hostControls"
    "hostRecipes"
    "hostLicenseInventory"
    "passthru"
    "phases"
  ];
in
  assert builtins.length build == 1 && builtins.length install == 1;
  assert builtins.length prefix >= 1;
  assert (builtins.head prefix).name == "unpack";
  assert builtins.length (builtins.filter (phase: phase.name == "unpack") prefix) == 1;
    mkDerivation ((builtins.removeAttrs logical privateFields)
      // {
        pname = logical.pname + "-native-compiler";
        outputs = ["out" "source"];
        passBuildScriptAsFile = true;
        nativeSpecification = specification;
        nativeToolchainRecord = builtins.toJSON (logical.nativeToolchain
          // {
            recipes = recipeRows;
            sourceSnapshot = "after-variant-patches-before-generated-build-artifacts";
            nativeNodeQualified = false;
          });
        passAsFile = ["nativeSpecification" "nativeToolchainRecord"];
        phases =
          prefix
          ++ [
            {
              name = "native-corresponding-source";
              script = ''
                mkdir -p "$source/build/recipes" "$source/patches" "$source/licenses"
                cp "$src" "$source/gem5-upstream.tar.gz"
                cp LICENSE "$source/licenses/LICENSE"
                ${patchCopies}
                ${recipeCopies}
                cp "$nativeSpecificationPath" "$source/build/native-compiler-inputs.json"
                cp "$nativeToolchainRecordPath" "$source/build/toolchain.json"
                # The actual invoked builder includes stdenv's automatic fixups.
                cp "$0" "$source/build/invoked-builder.sh"
                cp "$stdenv/setup.sh" "$source/build/stdenv-setup.sh"
                tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
                  -cf "$source/gem5-patched-source.tar" .
              '';
            }
          ]
          ++ build
          ++ [
            {
              name = "native-generated-context";
              script = ''
                # The existing C++ checks later use these exact generated headers.
                # No compiled object or mutable build directory is published.
                find build/ALL -type f \( -name '*.hh' -o -name '*.h' -o -name '*.inc' \
                  -o -path '*/gem5.build/config' \) -print | sort > generated-context.list
                tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
                  -cf "$source/build/generated-headers.tar" -T generated-context.list
              '';
            }
          ]
          ++ install;
      })
